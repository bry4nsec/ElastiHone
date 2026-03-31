"""Fetch and parse Elastic Defend behavioral protection rules from protections-artifacts.

Pulls rules from https://github.com/elastic/protections-artifacts (main branch),
which are the "Malicious Behavior Detection Alert" rules that run inside the
Elastic Agent's behavioral protection engine.

These rules use EQL and can be analyzed against logs-endpoint.events.* telemetry
since Elastic Agent forwards its event data to Elasticsearch.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ── TOML import ─────────────────────────────────────────────────────────────
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

# ── Constants ────────────────────────────────────────────────────────────────

GITHUB_API = "https://api.github.com"
GITHUB_RAW = "https://raw.githubusercontent.com"
REPO = "elastic/protections-artifacts"
BRANCH = "main"

PLATFORMS = ["linux", "windows", "macos", "cross-platform"]

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

# Map EQL event category → default index pattern
EVENT_INDEX_MAP = {
    "api": "logs-endpoint.events.api*",
    "process": "logs-endpoint.events.process*",
    "file": "logs-endpoint.events.file*",
    "registry": "logs-endpoint.events.registry*",
    "network": "logs-endpoint.events.network*",
    "dns": "logs-endpoint.events.network*",
    "library": "logs-endpoint.events.library*",
}

CACHE_TTL = 3600

# ── In-memory caches ────────────────────────────────────────────────────────

_LISTING_CACHE: dict[str, dict] = {}
_LISTING_TIMESTAMP: float = 0.0
_RULE_CONTENT_CACHE: dict[str, tuple[float, dict, str]] = {}


def _listing_is_fresh() -> bool:
    return bool(_LISTING_CACHE) and (time.time() - _LISTING_TIMESTAMP < CACHE_TTL)


def _tactic_from_filename(filename: str) -> str:
    basename = filename.rsplit("/", 1)[-1].removesuffix(".toml")
    for prefix, tactic in TACTIC_MAP.items():
        if basename.startswith(prefix + "_") or basename == prefix:
            return tactic
    return ""


def _humanize_name(filename: str) -> str:
    basename = filename.rsplit("/", 1)[-1].removesuffix(".toml")
    for prefix in TACTIC_MAP:
        if basename.startswith(prefix + "_"):
            basename = basename[len(prefix) + 1:]
            break
    return basename.replace("_", " ").title()


def _infer_indices_from_query(query: str) -> list[str]:
    """Infer target Elasticsearch indices from the EQL query.

    Parses the event category (e.g. 'process where', 'api where', 'file where')
    from an EQL query and maps to the corresponding logs-endpoint.events.* index.
    For sequences, includes all relevant indices.
    """
    indices = set()
    # Match event category at start or after sequence markers
    for match in re.finditer(r'\b(\w+)\s+where\b', query):
        category = match.group(1).lower()
        if category in EVENT_INDEX_MAP:
            indices.add(EVENT_INDEX_MAP[category])

    if not indices:
        # Fallback to wildcard
        return ["logs-endpoint.events.*"]

    return sorted(indices)


def _parse_behavioral_toml(toml_text: str) -> dict:
    """Parse a behavioral protection TOML rule into pipeline-compatible JSON.

    Behavioral rules differ from detection-rules:
    - Use os_list instead of index
    - Have actions (kill_process, etc.)
    - Use min_endpoint_version
    - No metadata.integration field
    """
    data = tomllib.loads(toml_text)
    rule = data.get("rule", {})

    result: dict[str, Any] = {}

    # Core fields
    for field in [
        "name", "description", "query", "language", "type",
        "risk_score", "tags", "threat",
    ]:
        if field in rule:
            result[field] = rule[field]

    # Rule ID
    if "id" in rule:
        result["rule_id"] = rule["id"]

    # Author and license
    result["author"] = rule.get("author", ["Elastic"])
    result["license"] = rule.get("license", "Elastic License v2")

    # Default type is EQL for behavioral rules
    result.setdefault("type", "eql")
    result.setdefault("language", "eql")

    # Map severity from risk_score (behavioral rules don't have severity field)
    risk = rule.get("risk_score", 75)
    if risk >= 73:
        result["severity"] = "critical"
    elif risk >= 47:
        result["severity"] = "high"
    elif risk >= 21:
        result["severity"] = "medium"
    else:
        result["severity"] = "low"
    result["risk_score"] = risk

    # Infer indices from query
    query = rule.get("query", "")
    result["index"] = _infer_indices_from_query(query)

    # Behavioral-specific fields (for display)
    result["_behavioral"] = {
        "os_list": rule.get("os_list", []),
        "version": rule.get("version", ""),
        "min_endpoint_version": rule.get("min_endpoint_version",
                                          data.get("internal", {}).get("min_endpoint_version", "")),
        "actions": data.get("actions", []),
    }

    # Metadata
    result["_metadata"] = {
        "source": "behavioral",
        "repo": REPO,
        "branch": BRANCH,
    }

    return result


def _extract_behavioral_summary(toml_text: str, file_path: str) -> dict | None:
    """Parse a behavioral TOML and extract summary info."""
    try:
        data = tomllib.loads(toml_text)
    except Exception as exc:
        logger.debug("Failed to parse behavioral TOML %s: %s", file_path, exc)
        return None

    rule = data.get("rule", {})

    # Extract MITRE info
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

    # Platform from file path
    platform = "unknown"
    for p in PLATFORMS:
        if f"rules/{p}/" in file_path:
            platform = p
            break

    # Determine query compatibility
    query = rule.get("query", "")
    uses_api_where = bool(re.search(r'\bapi\s+where\b', query))
    uses_ext_fields = "process.Ext." in query or "process.thread.Ext." in query

    return {
        "name": rule.get("name", _humanize_name(file_path)),
        "path": file_path,
        "platform": platform,
        "type": "eql",
        "language": "eql",
        "severity": "critical" if rule.get("risk_score", 75) >= 73
                    else "high" if rule.get("risk_score", 75) >= 47
                    else "medium",
        "risk_score": rule.get("risk_score", 75),
        "rule_id": rule.get("id", ""),
        "tactics": tactics,
        "techniques": techniques,
        "description": (rule.get("description", "") or "")[:200],
        "source": "behavioral",
        "version": rule.get("version", ""),
        "has_actions": bool(data.get("actions")),
        "api_rule": uses_api_where,
        "ext_fields": uses_ext_fields,
        "_enriched": True,
        "_is_behavioral": True,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Phase 1: Fast listing via Git Tree API
# ═══════════════════════════════════════════════════════════════════════════════


def _fetch_tree() -> list[dict]:
    """Fetch the full Git tree for behavioral rules."""
    url = f"{GITHUB_API}/repos/{REPO}/git/trees/{BRANCH}"
    params = {"recursive": "true"}

    try:
        with httpx.Client(timeout=60.0, verify=False) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            tree = resp.json()

        toml_files = []
        for item in tree.get("tree", []):
            path = item.get("path", "")
            if (
                path.startswith("behavior/rules/")
                and path.endswith(".toml")
                and item.get("type") == "blob"
            ):
                parts = path.split("/")
                if len(parts) >= 4 and parts[2] in PLATFORMS:
                    toml_files.append({
                        "path": path,
                        "sha": item.get("sha", ""),
                        "size": item.get("size", 0),
                    })

        logger.info("Behavioral rules tree: %d TOML files found", len(toml_files))
        return toml_files

    except Exception as exc:
        logger.error("Failed to fetch behavioral rules tree: %s", exc)
        return []


def _build_fast_listing() -> dict[str, dict]:
    """Build a fast listing from filenames only."""
    cache: dict[str, dict] = {}
    tree_files = _fetch_tree()

    for f in tree_files:
        path = f["path"]
        filename = path.rsplit("/", 1)[-1]

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
            "type": "eql",
            "language": "eql",
            "severity": "high",
            "risk_score": 75,
            "rule_id": "",
            "tactics": [tactic] if tactic else [],
            "techniques": [],
            "description": "",
            "source": "behavioral",
            "has_actions": False,
            "api_rule": False,
            "ext_fields": False,
            "_enriched": False,
            "_is_behavioral": True,
        }

    return cache


def _ensure_listing() -> None:
    global _LISTING_CACHE, _LISTING_TIMESTAMP

    if _listing_is_fresh():
        return

    logger.info("Refreshing behavioral protections listing cache...")
    _LISTING_CACHE = _build_fast_listing()
    _LISTING_TIMESTAMP = time.time()
    logger.info("Behavioral listing cache: %d rules found", len(_LISTING_CACHE))


def _fetch_raw_rule(file_path: str) -> str:
    url = f"{GITHUB_RAW}/{REPO}/{BRANCH}/{file_path}"
    try:
        with httpx.Client(timeout=30.0, verify=False) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:
        logger.error("Failed to fetch behavioral rule: %s — %s", file_path, exc)
        raise ValueError(f"Failed to fetch behavioral rule: {exc}") from exc


def _enrich_batch(paths: list[str]) -> None:
    """Enrich a batch of behavioral rule summaries with actual TOML metadata."""
    to_fetch = [p for p in paths if not _LISTING_CACHE.get(p, {}).get("_enriched", False)]
    if not to_fetch:
        return

    logger.info("Enriching %d behavioral rules...", len(to_fetch))

    for path in to_fetch:
        try:
            toml_text = _fetch_raw_rule(path)
            summary = _extract_behavioral_summary(toml_text, path)

            if summary is None:
                if path in _LISTING_CACHE:
                    _LISTING_CACHE[path]["_enriched"] = True
                continue

            _LISTING_CACHE[path] = summary

            # Also cache the parsed content
            _RULE_CONTENT_CACHE[path] = (
                time.time(),
                _parse_behavioral_toml(toml_text),
                toml_text,
            )

        except Exception as exc:
            logger.debug("Failed to enrich behavioral rule %s: %s", path, exc)
            if path in _LISTING_CACHE:
                _LISTING_CACHE[path]["_enriched"] = True


# ═══════════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════════


def list_behavioral_rules(
    platform: str = "",
    search: str = "",
    tactic: str = "",
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    """List behavioral protection rules from protections-artifacts.

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

    all_rules = list(_LISTING_CACHE.values())

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

    all_rules.sort(key=lambda r: r["name"])

    total = len(all_rules)
    start = (page - 1) * per_page
    end = start + per_page
    page_rules = all_rules[start:end]

    # Skip on-demand enrichment for listing speed — enrichment
    # happens only when a rule is clicked (fetch_behavioral_rule)

    return {
        "rules": page_rules,
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def fetch_behavioral_rule(file_path: str) -> dict:
    """Fetch a single behavioral rule from GitHub and return as JSON."""
    cached = _RULE_CONTENT_CACHE.get(file_path)
    if cached and (time.time() - cached[0] < CACHE_TTL):
        return cached[1]

    toml_text = _fetch_raw_rule(file_path)
    parsed = _parse_behavioral_toml(toml_text)
    _RULE_CONTENT_CACHE[file_path] = (time.time(), parsed, toml_text)
    return parsed


def get_behavioral_tactics() -> list[str]:
    """Return unique MITRE tactics from behavioral rules."""
    _ensure_listing()
    tactics = set()
    for rule in _LISTING_CACHE.values():
        for t in rule.get("tactics", []):
            if t:
                tactics.add(t)
    return sorted(tactics)
