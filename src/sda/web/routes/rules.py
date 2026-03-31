"""Rule import API routes — Kibana rules and behavioral protection rules."""

from __future__ import annotations

import logging
import re

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

from sda.web.dependencies import sanitize_search, sanitize_path

logger = logging.getLogger("sda.web")
router = APIRouter(prefix="/api", tags=["rules"])


@router.get("/rules/list")
async def api_rules_list(
    search: str = "", page: int = 1, rule_type: str = "",
    severity: str = "", source: str = "", status: str = "",
):
    """API: List detection rules from Kibana (HTMX endpoint)."""
    search = sanitize_search(search)
    rule_type = sanitize_search(rule_type, 50)
    severity = sanitize_search(severity, 50)
    source = sanitize_search(source, 50)
    status = sanitize_search(status, 50)
    page = max(1, min(page, 1000))
    from sda.kibana_client import list_rules

    try:
        result = list_rules(
            search=search, page=page, per_page=100,
            rule_type=rule_type, severity=severity,
            source=source, status=status,
        )
        rules = result["rules"]
        total = result["total"]

        if not rules:
            return HTMLResponse(
                '<div class="test-result-error">No rules found. '
                'Check your Kibana URL and credentials in Settings.</div>'
            )

        rows = ""
        for r in rules:
            severity_class = {
                "critical": "severity-critical",
                "high": "severity-high",
                "medium": "severity-medium",
                "low": "severity-low",
            }.get(r["severity"], "")
            enabled_badge = (
                '<span class="badge badge-enabled">ON</span>'
                if r["enabled"]
                else '<span class="badge badge-disabled">OFF</span>'
            )
            source_badge = (
                '<span class="badge badge-elastic">Elastic</span>'
                if r.get("immutable")
                else '<span class="badge badge-custom">Custom</span>'
            )
            type_icon = r.get("type_icon", "")
            type_label = r.get("type_label", r["type"].upper())
            icon_part = f"{type_icon} " if type_icon else ""
            rows += (
                f'<tr class="rule-row" data-rule-id="{r["id"]}"'
                f'    onclick="loadRule(\'{r["id"]}\')">'
                f'  <td class="rule-name-cell">{r["name"]}</td>'
                f'  <td><span class="type-badge type-{r["type"]}">{icon_part}{type_label}</span></td>'
                f'  <td><span class="severity-badge {severity_class}">{r["severity"]}</span></td>'
                f'  <td>{source_badge}</td>'
                f'  <td>{enabled_badge}</td>'
                f'</tr>'
            )

        per_page = 100
        total_pages = (total + per_page - 1) // per_page
        current_page = result["page"]

        pagination = ""
        if total_pages > 1:
            prev_disabled = 'disabled' if current_page <= 1 else ''
            next_disabled = 'disabled' if current_page >= total_pages else ''
            pagination = (
                f'<div class="pagination-controls">'
                f'  <button class="btn btn-sm btn-ghost" {prev_disabled} '
                f'    onclick="fetchRules({current_page - 1})">← Prev</button>'
                f'  <span class="pagination-info">Page {current_page} of {total_pages}</span>'
                f'  <button class="btn btn-sm btn-ghost" {next_disabled} '
                f'    onclick="fetchRules({current_page + 1})">Next →</button>'
                f'</div>'
            )

        html = (
            f'<div class="rules-summary">{total} rules found</div>'
            f'<table class="rules-table">'
            f'<thead><tr><th>Name</th><th>Type</th><th>Severity</th>'
            f'<th>Source</th><th>Status</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            f'{pagination}'
        )
        return HTMLResponse(html)
    except ValueError as exc:
        return HTMLResponse(
            f'<div class="test-result-error">Error: {exc}</div>'
        )


# ── JSON API endpoints (for React frontend) ──────────────────────────────
# NOTE: These MUST be registered BEFORE /rules/{rule_id} to prevent
#       FastAPI from matching 'json' as a rule_id path parameter.


@router.get("/rules/coverage")
async def api_rules_coverage():
    """API: Rule coverage gap — enabled vs disabled counts by severity,
    plus deprecated and no-integration rule lists."""
    from sda.kibana_client import get_rule_coverage_stats

    try:
        return get_rule_coverage_stats()
    except Exception as exc:
        logger.warning("Failed to get rule coverage: %s", exc)
        return {"by_severity": {}, "totals": {"enabled": 0, "disabled": 0, "total": 0}, "coverage_pct": 0}


@router.get("/rules/json")
async def api_rules_json(
    search: str = "", page: int = 1, rule_type: str = "",
    severity: str = "", source: str = "", status: str = "",
):
    """JSON API: List detection rules from Kibana."""
    search = sanitize_search(search)
    rule_type = sanitize_search(rule_type, 50)
    severity = sanitize_search(severity, 50)
    source = sanitize_search(source, 50)
    status = sanitize_search(status, 50)
    page = max(1, min(page, 1000))
    from sda.kibana_client import list_rules

    try:
        return list_rules(
            search=search, page=page, per_page=100,
            rule_type=rule_type, severity=severity,
            source=source, status=status,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/rules/{rule_id}")
async def api_rules_fetch(rule_id: str):
    """API: Fetch a single rule from Kibana and return as JSON."""
    rule_id = sanitize_search(rule_id, 100)
    if not re.match(r'^[a-zA-Z0-9_-]+$', rule_id):
        return JSONResponse({"error": "Invalid rule ID"}, status_code=400)
    from sda.kibana_client import fetch_rule

    try:
        rule = fetch_rule(rule_id)
        return JSONResponse(rule)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


# ── Behavioral Protection Rules ──────────────────────────────────────────

@router.get("/behavioral-rules/list")
async def api_behavioral_rules_list(
    search: str = "", platform: str = "",
    tactic: str = "", page: int = 1,
):
    """API: List behavioral protection rules from protections-artifacts."""
    search = sanitize_search(search)
    platform = sanitize_search(platform, 50)
    tactic = sanitize_search(tactic, 100)
    page = max(1, min(page, 1000))
    from sda.behavioral_rules import list_behavioral_rules

    try:
        result = list_behavioral_rules(
            platform=platform, search=search,
            tactic=tactic, page=page, per_page=50,
        )
        rules = result["rules"]
        total = result["total"]

        rows = ""
        for r in rules:
            severity_class = {
                "critical": "severity-critical",
                "high": "severity-high",
                "medium": "severity-medium",
                "low": "severity-low",
            }.get(r.get("severity", "high"), "")

            platform_icons = {
                "linux": "🐧", "windows": "🪟",
                "macos": "🍎", "cross-platform": "🌐",
            }
            platform_icon = platform_icons.get(r.get("platform", ""), "")
            tactics_str = ", ".join(r.get("tactics", [])[:2]) or "—"

            compat = ""
            if r.get("api_rule"):
                compat = '<span class="compat-badge compat-api" title="Uses API events — may not match logs-endpoint indices">⚠ API</span>'
            elif r.get("ext_fields"):
                compat = '<span class="compat-badge compat-ext" title="Uses Ext fields — may need endpoint-specific indices">⚡ Ext</span>'

            path = r.get("path", "")
            rows += (
                f'<tr class="rule-row" data-rule-path="{path}"'
                f'    onclick="loadBehavioralRule(\'{path}\')">'
                f'  <td class="rule-name-cell">{r["name"]}{compat}</td>'
                f'  <td><span class="type-badge type-eql">EQL</span></td>'
                f'  <td><span class="severity-badge {severity_class}">{r.get("severity", "high")}</span></td>'
                f'  <td>{platform_icon} {r.get("platform", "")}</td>'
                f'  <td class="tactic-cell">{tactics_str}</td>'
                f'</tr>'
            )

        per_page = 50
        total_pages = (total + per_page - 1) // per_page
        current_page = result["page"]

        pagination = ""
        if total_pages > 1:
            prev_disabled = 'disabled' if current_page <= 1 else ''
            next_disabled = 'disabled' if current_page >= total_pages else ''
            pagination = (
                f'<div class="pagination-controls">'
                f'  <button class="btn btn-sm btn-ghost" {prev_disabled} '
                f'    onclick="fetchBehavioralRules({current_page - 1})">← Prev</button>'
                f'  <span class="pagination-info">Page {current_page} of {total_pages} '
                f'  ({total} rules)</span>'
                f'  <button class="btn btn-sm btn-ghost" {next_disabled} '
                f'    onclick="fetchBehavioralRules({current_page + 1})">Next →</button>'
                f'</div>'
            )

        html = (
            f'<div class="rules-summary">{total} Behavioral Protection rules</div>'
            f'<table class="rules-table">'
            f'<thead><tr><th>Name</th><th>Type</th><th>Severity</th>'
            f'<th>Platform</th><th>Tactic</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            f'{pagination}'
        )
        return HTMLResponse(html)
    except Exception as exc:
        logger.error("Behavioral rules list error: %s", exc)
        return HTMLResponse(
            f'<div class="test-result-error">Error: {exc}</div>'
        )


@router.get("/behavioral-rules/tactics")
async def api_behavioral_rules_tactics():
    """API: Return available MITRE tactics from behavioral rules."""
    from sda.behavioral_rules import get_behavioral_tactics
    return {"tactics": get_behavioral_tactics()}


@router.get("/behavioral-rules/fetch")
async def api_behavioral_rules_fetch(path: str):
    """API: Fetch a single behavioral rule by its file path."""
    try:
        path = sanitize_path(path)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    from sda.behavioral_rules import fetch_behavioral_rule

    try:
        rule_json = fetch_behavioral_rule(path)
        return JSONResponse(rule_json)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:
        logger.error("Failed to fetch behavioral rule %s: %s", path, exc)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/behavioral-rules/json")
async def api_behavioral_rules_json(
    search: str = "", platform: str = "",
    tactic: str = "", page: int = 1,
):
    """JSON API: List behavioral protection rules."""
    search = sanitize_search(search)
    platform = sanitize_search(platform, 50)
    tactic = sanitize_search(tactic, 100)
    page = max(1, min(page, 1000))
    from sda.behavioral_rules import list_behavioral_rules

    try:
        return list_behavioral_rules(
            platform=platform, search=search,
            tactic=tactic, page=page, per_page=50,
        )
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/alerts/subtypes")
async def api_alert_subtypes(rule_name: str = "", rule_uuid: str = "", days: int = 7):
    """API: Get alert subtypes for an envelope rule.

    Returns aggregation of alerts by 'message' field, showing individual
    alert sub-types (e.g. 'Shellcode Injection') within envelope rules
    like 'Memory Threat - Detected - Elastic Defend'.
    """
    if not rule_name:
        return JSONResponse({"error": "rule_name is required"}, status_code=400)

    from sda.kibana_client import get_alert_subtypes

    try:
        return get_alert_subtypes(
            rule_name=rule_name,
            days=min(max(days, 1), 90),
            rule_uuid=rule_uuid,
        )
    except Exception as exc:
        logger.error("Alert subtypes error: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=500)

