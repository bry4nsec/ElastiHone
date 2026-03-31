"""Settings API routes — config, health, and ES connection test."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from sda.web.dependencies import test_es_connection

router = APIRouter(prefix="/api", tags=["settings"])


@router.post("/es/test")
async def api_es_test():
    """Test Elasticsearch connection — returns JSON."""
    result = test_es_connection()
    return result


@router.get("/config")
async def api_config():
    """API: Return current configuration (with masked secrets)."""
    from sda.config import get_config_display
    return get_config_display()


@router.get("/health")
async def api_health():
    """API: Health check."""
    return {"status": "ok", "version": "0.2.0"}


@router.post("/settings")
async def api_settings_update(request: Request):
    """API: Update configuration from JSON body."""
    from sda.config import update_config

    data = await request.json()
    section = data.get("section", "")
    values = data.get("values", {})

    overrides = {}
    if section == "es":
        for field in ["url", "api_key", "username", "password", "production_indices"]:
            if field in values and values[field]:
                overrides[f"es.{field}"] = values[field]
        if "verify_certs" in values:
            overrides["es.verify_certs"] = bool(values["verify_certs"])
        if "noise_lookback_days" in values:
            try:
                overrides["es.noise_lookback_days"] = int(values["noise_lookback_days"])
            except (ValueError, TypeError):
                pass
    elif section == "kibana":
        for field in ["kibana_url", "kibana_space", "kibana_username", "kibana_password", "kibana_api_key"]:
            if field in values and values[field]:
                overrides[f"es.{field}"] = values[field]
    elif section == "llm":
        for field in ["provider", "base_url", "api_key", "deployment_name"]:
            if field in values and values[field]:
                overrides[f"llm.{field}"] = values[field]
        if "temperature" in values:
            try:
                overrides["llm.temperature"] = float(values["temperature"])
            except (ValueError, TypeError):
                pass
        if "max_iterations" in values:
            try:
                overrides["llm.max_iterations"] = int(values["max_iterations"])
            except (ValueError, TypeError):
                pass

    try:
        update_config(**overrides)
        return {"success": True, "message": f"{section} configuration updated"}
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/metrics")
async def api_metrics():
    """API: Aggregated analysis statistics as JSON."""
    from collections import defaultdict
    from sda.web.dependencies import analyses

    all_analyses = [a for a in analyses.values() if a.get("status") == "done"]

    verdicts = {"approve": 0, "review": 0, "tune": 0, "reject": 0, "error": 0}
    severities = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    total_tokens = 0
    fpr_values = []

    for a in all_analyses:
        v = a.get("verdict", "error")
        verdicts[v] = verdicts.get(v, 0) + 1

        sev = (a.get("severity") or "medium").lower()
        if sev in severities:
            severities[sev] += 1

        tokens = a.get("ai_tokens_used", 0) or 0
        total_tokens += tokens

        fpr = a.get("fpr")
        if fpr is not None and v != "error":
            fpr_values.append(fpr)

    avg_fpr = round(sum(fpr_values) / len(fpr_values), 4) if fpr_values else 0

    rule_groups: dict[str, list[dict]] = defaultdict(list)
    for a in all_analyses:
        name = a.get("rule_name", "Unknown")
        rule_groups[name].append(a)

    rule_summaries = []
    for name, rule_analyses in sorted(rule_groups.items()):
        sorted_runs = sorted(rule_analyses, key=lambda x: x.get("analysis_id", ""))
        latest = sorted_runs[-1]
        first = sorted_runs[0]
        latest_apd = latest.get("estimated_alerts_per_day", 0) or 0
        first_apd = first.get("estimated_alerts_per_day", 0) or 0
        improvement = None
        if len(sorted_runs) > 1 and first_apd > 0:
            improvement = round(((first_apd - latest_apd) / first_apd) * 100, 1)

        rule_summaries.append({
            "name": name,
            "analyses_count": len(sorted_runs),
            "latest_verdict": latest.get("verdict", "error"),
            "latest_alerts": latest.get("actual_alert_count", latest.get("noise_hits", 0)),
            "latest_apd": latest_apd,
            "latest_fpr": latest.get("fpr", 0),
            "improvement_pct": improvement,
            "rule_type": latest.get("rule_type", ""),
            "severity": latest.get("severity", ""),
            "latest_id": latest.get("analysis_id", ""),
            "ai_tokens": latest.get("ai_tokens_used", 0) or 0,
        })

    total_alerts_per_day = sum(
        a.get("estimated_alerts_per_day", 0) or 0
        for a in all_analyses if a.get("verdict") != "error"
    )

    # Count applied exceptions from DB (best effort)
    exceptions_count = 0
    try:
        from sda.db import list_exceptions
        import asyncio
        exceptions_data = await list_exceptions()
        exceptions_count = len(exceptions_data) if isinstance(exceptions_data, list) else 0
    except Exception:
        pass

    return {
        "total_analyses": len(all_analyses),
        "verdicts": verdicts,
        "severities": severities,
        "rule_summaries": rule_summaries,
        "unique_rules": len(rule_groups),
        "total_alerts_per_day": round(total_alerts_per_day, 1),
        "avg_fpr": avg_fpr,
        "total_ai_tokens": total_tokens,
        "exceptions_applied": exceptions_count,
    }
