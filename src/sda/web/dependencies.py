"""Shared dependencies for ElastiHone web routes.

Provides the Jinja2 templates instance (with custom filters),
in-memory analysis store, ES connection tester, and input sanitisers.
"""

from __future__ import annotations

import json
import re
import logging
from pathlib import Path

from fastapi.templating import Jinja2Templates

logger = logging.getLogger("sda.web")

WEB_DIR = Path(__file__).parent
TEMPLATES_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"

# ── Input Sanitisation ────────────────────────────────────────────────────
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
MAX_SEARCH_LEN = 200
MAX_CONTENT_LEN = 500_000  # 500KB rule content limit


def sanitize_search(value: str, max_len: int = MAX_SEARCH_LEN) -> str:
    """Sanitise a user-provided search string."""
    value = _HTML_TAG_RE.sub("", value)
    value = _CONTROL_CHAR_RE.sub("", value)
    return value.strip()[:max_len]


def sanitize_path(value: str) -> str:
    """Sanitise a file path parameter — prevent traversal."""
    value = value.strip()
    if ".." in value or value.startswith("/") or "\\" in value:
        raise ValueError("Invalid path")
    if not value.endswith(".toml"):
        raise ValueError("Only .toml files allowed")
    return value


# ── In-memory Analysis Store ──────────────────────────────────────────────
# Shared mutable dict — all route modules reference the same instance.
analyses: dict[str, dict] = {}


# ── ES Connection Test ────────────────────────────────────────────────────
def test_es_connection() -> dict:
    """Test Elasticsearch connectivity and return status."""
    from sda.config import get_config

    cfg = get_config().es
    try:
        from elasticsearch import Elasticsearch
        kwargs = {
            "hosts": [cfg.url],
            "verify_certs": cfg.verify_certs,
            "request_timeout": 10,
        }
        if cfg.api_key:
            kwargs["api_key"] = cfg.api_key
        elif cfg.username and cfg.password:
            kwargs["basic_auth"] = (cfg.username, cfg.password)
        if cfg.ca_certs:
            kwargs["ca_certs"] = cfg.ca_certs

        es = Elasticsearch(**kwargs)
        health = es.cluster.health()
        info = es.info()
        es.close()
        version = info.get("version", {}).get("number", "unknown")
        return {
            "connected": True,
            "cluster_name": health.get("cluster_name", "unknown"),
            "version": version,
            "status": health.get("status", "unknown"),
            "nodes": health.get("number_of_nodes", 0),
        }
    except Exception as exc:
        return {"connected": False, "error": str(exc)}


# ── Jinja2 Templates (singleton) ─────────────────────────────────────────
_templates: Jinja2Templates | None = None


def get_templates() -> Jinja2Templates:
    """Return the shared Jinja2Templates instance with custom filters."""
    global _templates
    if _templates is not None:
        return _templates

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Markdown filter
    def _md_filter(text: str) -> str:
        from markupsafe import Markup
        from markdown_it import MarkdownIt
        md = MarkdownIt("commonmark", {"breaks": True, "html": True})
        md.enable(["table", "strikethrough"])
        return Markup(md.render(text))

    templates.env.filters["markdown"] = _md_filter

    # KQL extraction filter
    def _extract_kql(recommendations: list[str]) -> list[dict]:
        """Extract JSON exception entries from AI markdown and convert to KQL."""
        results = []
        for rec in recommendations:
            for match in re.finditer(
                r'```json\s*(\{[^`]*?"entries"[^`]*?\})\s*```', rec, re.DOTALL
            ):
                try:
                    data = json.loads(match.group(1))
                    entries = data.get("entries", [])
                    if not entries:
                        continue
                    kql_parts = []
                    for entry in entries:
                        field = entry.get("field", "")
                        value = entry.get("value", "")
                        etype = entry.get("type", "match")
                        if etype == "match":
                            kql_parts.append(f'{field}: "{value}"')
                        elif etype == "match_any":
                            vals = [v.strip() for v in value.split(",")]
                            quoted = " OR ".join(f'"{v}"' for v in vals)
                            kql_parts.append(f'{field}: ({quoted})')
                        elif etype == "wildcard":
                            kql_parts.append(f'{field}: "{value}"')
                        elif etype == "exists":
                            kql_parts.append(f'{field}: *')
                    kql = " AND ".join(kql_parts)
                    results.append({
                        "kql": kql,
                        "entries_json": json.dumps(data, indent=2),
                        "fields": [
                            (e.get("field", ""), e.get("value", ""))
                            for e in entries
                        ],
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
        return results

    templates.env.filters["extract_kql"] = _extract_kql

    # MITRE ATT&CK URL helper
    def _mitre_url(technique_id: str) -> str:
        tid = technique_id.strip().upper()
        if "." in tid:
            parts = tid.split(".", 1)
            return f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}"
        return f"https://attack.mitre.org/techniques/{tid}"

    templates.env.filters["mitre_url"] = _mitre_url

    _templates = templates
    return _templates
