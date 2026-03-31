"""Fetch and parse Elastic Defend rules from the public detection-rules repo.

Pulls individual behavioral TOML rules from
https://github.com/elastic/detection-rules (branch 8.18),
filters for Endpoint Security integration rules, and converts them
into the same JSON format that `parsers.elastic_parser.parse_elastic_rule()`
consumes — enabling independent noise analysis via the existing pipeline.

Architecture:
    Phase 1 (fast) — Git Tree API returns all filenames in one call.
                     Filenames encode tactic via naming convention.
    Phase 2 (on-demand) — Individual TOML files fetched when user selects a rule,
                          then parsed and cached.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── TOML import (Python 3.11+ stdlib or tomli fallback) ─────────────────────
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

# ── Constants ────────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
REPO = "elastic/detection-rules"
BRANCH = "8.18"

# Rule subdirectories to scan
PLATFORMS = ["linux", "windows", "macos", "cross-platform"]

# Map filename prefix → MITRE tactic display name
TACTIC_MAP = {
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "initial_access": "Initial Access",
    "lateral_movement": "Lateral Movement",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
}

# Cache TTL in seconds (1 hour)
CACHE_TTL = 3600

# ── In-memory caches ────────────────────────────────────────────────────────

# Phase 1: fast listing cache — path → summary dict
_LISTING_CACHE: dict[str, dict] = {}
_LISTING_TIMESTAMP: float = 0.0

# Phase 2: per-rule content cache — path → (timestamp, parsed_json, toml_text)
_RULE_CONTENT_CACHE: dict[str, tuple[float, dict, str]] = {}

# Enriched rules cache — path → full summary with MITRE details
_ENRICHED_CACHE: dict[str, dict] = {}
_ENRICHED_TIMESTAMP: float = 0.0


def _listing_is_fresh() -> bool:
    return bool(_LISTING_CACHE) and (time.time() - _LISTING_TIMESTAMP < CACHE_TTL)


def _tactic_from_filename(filename: str) -> str:
    """Extract the MITRE tactic from a rule filename convention.

    Example: 'execution_curl_cve_2023_38545_heap_overflow.toml' → 'Execution'
    """
    basename = filename.rsplit("/", 1)[-1].removesuffix(".toml")
    for prefix, tactic in TACTIC_MAP.items():
        if basename.startswith(prefix + "_") or basename == prefix:
            return tactic
    return ""


def _humanize_name(filename: str) -> str:
    """Convert a filename to a human-readable rule name.

    Example: 'execution_curl_cve_2023_38545_heap_overflow.toml'
             → 'Curl CVE 2023 38545 Heap Overflow'
    (The actual name will be replaced when the TOML is parsed.)
    """
    basename = filename.rsplit("/", 1)[-1].removesuffix(".toml")

    # Remove tactic prefix
    for prefix in TACTIC_MAP:
        if basename.startswith(prefix + "_"):
            basename = basename[len(prefix) + 1:]
            break

    return basename.replace("_", " ").title()


def _parse_toml_rule(toml_text: str) -> dict:
    """Parse a TOML rule into a dict compatible with elastic_parser.

    Extracts [rule] section and maps it to the JSON format expected by
    parse_elastic_rule(), so the full downstream pipeline works unchanged.
    """
    data = tomllib.loads(toml_text)
    metadata = data.get("metadata", {})
    rule = data.get("rule", {})

    # Build the JSON structure that parse_elastic_rule() expects
    result: dict[str, Any] = {}

    # Direct mappings from [rule] section
    for field in [
        "name", "description", "query", "language", "type", "severity",
        "risk_score", "rule_id", "index", "tags", "threat",
        "threshold", "new_terms", "alert_suppression",
        "max_signals", "interval",
    ]:
        if field in rule:
            result[field] = rule[field]

    # Author and license
    result["author"] = rule.get("author", ["Elastic"])
    result["license"] = rule.get("license", "Elastic License v2")

    # References
    if "references" in rule:
        result["references"] = rule["references"]

    # Schedule — map 'from' key (reserved in Python)
    if "from" in rule:
        result["from"] = rule["from"]

    # Metadata enrichment for downstream display
    result["_metadata"] = {
        "integration": metadata.get("integration", []),
        "maturity": metadata.get("maturity", "production"),
        "creation_date": metadata.get("creation_date", ""),
        "updated_date": metadata.get("updated_date", ""),
        "source": "github",
        "repo": REPO,
        "branch": BRANCH,
    }

    # Ensure required fields have defaults
    result.setdefault("type", "query")
    result.setdefault("language", "kuery")
    result.setdefault("severity", "medium")
    result.setdefault("risk_score", 50)
    result.setdefault("index", ["logs-endpoint.events.*"])

    return result


def _extract_rule_summary_from_toml(toml_text: str, file_path: str) -> dict | None:
    """Parse a TOML rule and extract rich summary info.

    Returns None if the rule is not an Endpoint Security integration rule.
    """
    try:
        data = tomllib.loads(toml_text)
    except Exception as exc:
        logger.debug("Failed to parse TOML for %s: %s", file_path, exc)
        return None

    metadata = data.get("metadata", {})
    rule = data.get("rule", {})

    # Filter: only Endpoint Security integration rules
    integrations = metadata.get("integration", [])
    if isinstance(integrations, str):
        integrations = [integrations]
    if "endpoint" not in integrations:
        return None

    # Extract full MITRE info
    tactics = []
    techniques = []
    for t in rule.get("threat", []):
        tactic = t.get("tactic", {})
        if tactic_name := tactic.get("name"):
            tactics.append(tactic_name)
        for tech in t.get("technique", []):
            if tech_id := tech.get("id"):
                techniques.append(tech_id)
            for sub in tech.get("subtechnique", []):
                if sub_id := sub.get("id"):
                    techniques.append(sub_id)

    # Determine platform from file path
    platform = "unknown"
    for p in PLATFORMS:
        if f"rules/{p}/" in file_path:
            platform = p
            break

    rule_type = rule.get("type", "query")
    language = rule.get("language", "kuery")

    return {
        "name": rule.get("name", _humanize_name(file_path)),
        "path": file_path,
        "platform": platform,
        "type": rule_type,
        "language": language,
        "severity": rule.get("severity", "medium"),
        "risk_score": rule.get("risk_score", 50),
        "rule_id": rule.get("rule_id", ""),
        "tactics": tactics,
        "techniques": techniques,
        "maturity": metadata.get("maturity", ""),
        "description": (rule.get("description", "") or "")[:200],
        "source": "github",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Fast listing via Git Tree API
# ═══════════════════════════════════════════════════════════════════════════════


def _fetch_tree() -> list[dict]:
    """Fetch the full Git tree for the rules/ directory.

    Uses the Git Trees API with recursive=true to get ALL file paths
    in a single HTTP call — massively faster than listing each directory.

    Returns list of dicts with 'path' and 'sha' for .toml files.
    """
    url = f"{GITHUB_API}/repos/{REPO}/git/trees/{BRANCH}"
    params = {"recursive": "true"}

    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            tree = resp.json()

        toml_files = []
        for item in tree.get("tree", []):
            path = item.get("path", "")
            if (
                path.startswith("rules/")
                and path.endswith(".toml")
                and item.get("type") == "blob"
            ):
                # Check if it's in one of our platform directories
                parts = path.split("/")
                if len(parts) >= 3 and parts[1] in PLATFORMS:
                    toml_files.append({
                        "path": path,
                        "sha": item.get("sha", ""),
                        "size": item.get("size", 0),
                    })

        logger.info("Git tree API returned %d rule files across all platforms", len(toml_files))
        return toml_files

    except Exception as exc:
        logger.error("Failed to fetch Git tree: %s", exc)
        return []


def _build_fast_listing() -> dict[str, dict]:
    """Build a fast listing from filenames only (no TOML parsing).

    Creates preliminary summaries from the filename convention.
    These are enriched on-demand when the user browses.
    """
    cache: dict[str, dict] = {}
    tree_files = _fetch_tree()

    for f in tree_files:
        path = f["path"]
        filename = path.rsplit("/", 1)[-1]

        # Skip non-standard files
        if filename.startswith("_") or filename.startswith("."):
            continue

        platform = "unknown"
        for p in PLATFORMS:
            if f"rules/{p}/" in path:
                platform = p
                break

        tactic = _tactic_from_filename(filename)
        name = _humanize_name(filename)

        cache[path] = {
            "name": name,
            "path": path,
            "platform": platform,
            "type": "unknown",  # Will be enriched on-demand
            "language": "unknown",
            "severity": "medium",
            "risk_score": 50,
            "rule_id": "",
            "tactics": [tactic] if tactic else [],
            "techniques": [],
            "maturity": "",
            "description": "",
            "source": "github",
            "_enriched": False,
        }

    return cache


def _ensure_listing() -> None:
    """Ensure the listing cache is populated."""
    global _LISTING_CACHE, _LISTING_TIMESTAMP

    if _listing_is_fresh():
        return

    logger.info("Refreshing GitHub rules listing cache...")
    _LISTING_CACHE = _build_fast_listing()
    _LISTING_TIMESTAMP = time.time()
    logger.info("GitHub listing cache: %d rule files found", len(_LISTING_CACHE))


def _enrich_batch(paths: list[str], max_concurrent: int = 10) -> None:
    """Enrich a batch of rule summaries with actual TOML metadata.

    Downloads and parses the TOMLs to get accurate name, type, severity,
    and MITRE classification. Filters out non-endpoint rules.
    """
    to_fetch = [p for p in paths if not _LISTING_CACHE.get(p, {}).get("_enriched", False)]
    if not to_fetch:
        return

    logger.info("Enriching %d rules from GitHub...", len(to_fetch))

    for path in to_fetch:
        try:
            toml_text = _fetch_raw_rule(path)
            summary = _extract_rule_summary_from_toml(toml_text, path)

            if summary is None:
                # Not an endpoint rule — mark as enriched but flag for removal
                if path in _LISTING_CACHE:
                    _LISTING_CACHE[path]["_enriched"] = True
                    _LISTING_CACHE[path]["_is_endpoint"] = False
                continue

            summary["_enriched"] = True
            summary["_is_endpoint"] = True
            _LISTING_CACHE[path] = summary

            # Cache the content too
            _RULE_CONTENT_CACHE[path] = (time.time(), _parse_toml_rule(toml_text), toml_text)

        except Exception as exc:
            logger.debug("Failed to enrich %s: %s", path, exc)
            if path in _LISTING_CACHE:
                _LISTING_CACHE[path]["_enriched"] = True
                _LISTING_CACHE[path]["_is_endpoint"] = False


def _fetch_raw_rule(file_path: str) -> str:
    """Fetch raw TOML content for a rule from GitHub."""
    url = f"{GITHUB_RAW}/{REPO}/{BRANCH}/{file_path}"

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:
        logger.error("Failed to fetch rule from GitHub: %s — %s", file_path, exc)
        raise ValueError(f"Failed to fetch rule from GitHub: {exc}") from exc


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════


def list_endpoint_rules(
    platform: str = "",
    search: str = "",
    tactic: str = "",
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """List Elastic Defend behavioral rules from GitHub.

    Uses a two-phase approach:
    1. Fast listing from Git Tree API (filenames only, one HTTP call)
    2. On-demand enrichment when the user paginates / filters

    Args:
        platform: Filter by platform (linux/windows/macos/cross-platform).
        search: Case-insensitive search on rule name.
        tactic: Filter by MITRE ATT&CK tactic name.
        page: Page number (1-indexed).
        per_page: Results per page.

    Returns:
        Dict with 'rules' list and 'total' count.
    """
    _ensure_listing()

    # Apply filters
    all_rules = list(_LISTING_CACHE.values())

    # Filter out rules known to NOT be endpoint rules
    all_rules = [r for r in all_rules if r.get("_is_endpoint", True)]

    if platform:
        all_rules = [r for r in all_rules if r["platform"] == platform]

    if search:
        search_lower = search.lower()
        all_rules = [r for r in all_rules if search_lower in r["name"].lower()]

    if tactic:
        tactic_lower = tactic.lower()
        all_rules = [
            r for r in all_rules
            if any(tactic_lower in t.lower() for t in r.get("tactics", []))
        ]

    # Sort by name
    all_rules.sort(key=lambda r: r["name"])

    # Paginate
    total = len(all_rules)
    start = (page - 1) * per_page
    end = start + per_page
    page_rules = all_rules[start:end]

    # Enrich the page's rules if needed (lazy enrichment)
    paths_to_enrich = [r["path"] for r in page_rules if not r.get("_enriched", False)]
    if paths_to_enrich:
        _enrich_batch(paths_to_enrich)

        # Re-fetch the enriched versions and re-filter
        refreshed = []
        for r in page_rules:
            updated = _LISTING_CACHE.get(r["path"], r)
            if updated.get("_is_endpoint", True):
                refreshed.append(updated)
        page_rules = refreshed

    return {
        "rules": page_rules,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def fetch_github_rule(file_path: str) -> dict:
    """Fetch a single TOML rule from GitHub and return as JSON.

    The returned dict is compatible with parse_elastic_rule() from
    elastic_parser.py, enabling the full analysis pipeline.

    Args:
        file_path: Rule path relative to repo root
                   (e.g. 'rules/linux/execution_curl_cve_2023_38545_heap_overflow.toml').

    Returns:
        JSON-compatible dict for the rule.
    """
    # Check content cache
    cached = _RULE_CONTENT_CACHE.get(file_path)
    if cached and (time.time() - cached[0] < CACHE_TTL):
        return cached[1]

    toml_text = _fetch_raw_rule(file_path)
    parsed = _parse_toml_rule(toml_text)
    _RULE_CONTENT_CACHE[file_path] = (time.time(), parsed, toml_text)
    return parsed


def get_cached_rule_count() -> int:
    """Return the number of cached rule file paths."""
    return len(_LISTING_CACHE)


def get_available_tactics() -> list[str]:
    """Return a sorted list of unique MITRE tactics from all known rules."""
    _ensure_listing()
    tactics = set()
    for rule in _LISTING_CACHE.values():
        for t in rule.get("tactics", []):
            if t:
                tactics.add(t)
    return sorted(tactics)


def get_available_platforms() -> list[str]:
    """Return platforms that have rules."""
    _ensure_listing()
    platforms = set()
    for rule in _LISTING_CACHE.values():
        if rule.get("platform") and rule["platform"] != "unknown":
            platforms.add(rule["platform"])
    return sorted(platforms)
