"""HTML page routes — renders Jinja2 templates for the UI."""

from __future__ import annotations

import json
import logging
from collections import defaultdict

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from sda.web.dependencies import analyses, get_templates, test_es_connection

logger = logging.getLogger("sda.web")
router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page — rule submission form."""
    from sda.config import get_config
    templates = get_templates()
    cfg = get_config()
    es_status = test_es_connection()
    return templates.TemplateResponse(
        request, "index.html",
        context={
            "analyses": list(analyses.values()),
            "es_connected": es_status.get("connected", False),
            "es_cluster": es_status.get("cluster_name", ""),
            "es_version": es_status.get("version", ""),
            "config": cfg,
        },
    )


@router.get("/report/{analysis_id}", response_class=HTMLResponse)
async def view_report(request: Request, analysis_id: str):
    """View a specific analysis report."""
    templates = get_templates()
    report = analyses.get(analysis_id)
    if not report:
        return templates.TemplateResponse(
            request, "index.html",
            context={
                "error": f"Analysis {analysis_id} not found.",
                "analyses": list(analyses.values()),
                "es_connected": False,
            },
        )
    kibana_url = ""
    kibana_space = ""
    try:
        from sda.config import get_config
        cfg = get_config()
        kibana_url = cfg.es.kibana_url or ""
        kibana_space = cfg.es.kibana_space or ""
    except Exception:
        pass

    is_behavioral = (
        report.get("is_behavioral", False)
        or (report.get("noise_hits", 0) == 0 and report.get("actual_alert_count", -1) > 0)
    )

    return templates.TemplateResponse(
        request, "report.html",
        context={
            "report": report,
            "kibana_url": kibana_url,
            "kibana_space": kibana_space,
            "is_behavioral": is_behavioral,
        },
    )


@router.get("/metrics", response_class=HTMLResponse)
async def metrics_page(request: Request):
    """Metrics overview — aggregated analysis statistics."""
    templates = get_templates()
    all_analyses = [a for a in analyses.values() if a.get("status") == "done"]

    verdicts = {"approve": 0, "review": 0, "tune": 0, "reject": 0, "error": 0}
    for a in all_analyses:
        v = a.get("verdict", "error")
        verdicts[v] = verdicts.get(v, 0) + 1

    rule_groups: dict[str, list[dict]] = defaultdict(list)
    for a in all_analyses:
        name = a.get("rule_name", "Unknown")
        rule_groups[name].append(a)

    rule_summaries = []
    for name, rule_analyses in sorted(rule_groups.items()):
        sorted_runs = sorted(
            rule_analyses, key=lambda x: x.get("analysis_id", ""),
        )
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
            "latest_alerts": latest.get(
                "actual_alert_count", latest.get("noise_hits", "N/A")
            ),
            "latest_apd": latest_apd,
            "improvement_pct": improvement,
            "rule_type": latest.get("rule_type", ""),
            "severity": latest.get("severity", ""),
            "latest_id": latest.get("analysis_id", ""),
        })

    verdict_order = {"reject": 0, "review": 1, "approve": 2, "error": 3}
    rule_summaries.sort(key=lambda r: verdict_order.get(r["latest_verdict"], 99))

    total_alerts_per_day = sum(
        a.get("estimated_alerts_per_day", 0) or 0
        for a in all_analyses if a.get("verdict") != "error"
    )

    return templates.TemplateResponse(
        request, "metrics.html",
        context={
            "total_analyses": len(all_analyses),
            "verdicts": verdicts,
            "rule_summaries": rule_summaries,
            "unique_rules": len(rule_groups),
            "total_alerts_per_day": round(total_alerts_per_day, 1),
        },
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Settings page — configure ES and AI connections."""
    from sda.config import get_config, get_config_display
    templates = get_templates()
    es_status = test_es_connection()
    return templates.TemplateResponse(
        request, "settings.html",
        context={
            "config": get_config(),
            "config_json": json.dumps(get_config_display(), indent=2, default=str),
            "es_connected": es_status.get("connected", False),
        },
    )


@router.post("/settings", response_class=HTMLResponse)
async def settings_update(request: Request):
    """Update configuration from settings form."""
    from sda.config import get_config, get_config_display, update_config
    templates = get_templates()

    form = await request.form()
    section = form.get("section", "")

    overrides = {}
    if section == "es":
        for field in ["url", "api_key", "username", "password", "production_indices"]:
            val = form.get(f"es_{field}", "")
            if val:
                overrides[f"es.{field}"] = val
        verify = form.get("es_verify_certs", "true")
        overrides["es.verify_certs"] = verify == "true"
        days = form.get("es_noise_lookback_days", "7")
        try:
            overrides["es.noise_lookback_days"] = int(days)
        except ValueError:
            pass
    elif section == "kibana":
        for field in ["kibana_url", "kibana_space", "kibana_username", "kibana_password", "kibana_api_key"]:
            val = form.get(f"es_{field}", "")
            if val:
                overrides[f"es.{field}"] = val
    elif section == "llm":
        for field in ["provider", "base_url", "api_key", "deployment_name"]:
            val = form.get(f"llm_{field}", "")
            if val:
                overrides[f"llm.{field}"] = val
        temp = form.get("llm_temperature", "")
        if temp:
            try:
                overrides["llm.temperature"] = float(temp)
            except ValueError:
                pass
        iters = form.get("llm_max_iterations", "")
        if iters:
            try:
                overrides["llm.max_iterations"] = int(iters)
            except ValueError:
                pass

    try:
        update_config(**overrides)
        section_names = {"es": "Elasticsearch", "kibana": "Kibana", "llm": "AI"}
        success_msg = f"{section_names.get(section, section)} configuration updated."
        error_msg = None
    except Exception as exc:
        success_msg = None
        error_msg = f"Failed to update config: {exc}"

    es_status = test_es_connection()
    return templates.TemplateResponse(
        request, "settings.html",
        context={
            "config": get_config(),
            "config_json": json.dumps(get_config_display(), indent=2, default=str),
            "es_connected": es_status.get("connected", False),
            "success": success_msg,
            "error": error_msg,
        },
    )


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    """History page — browse past analyses."""
    templates = get_templates()
    return templates.TemplateResponse(request, "history.html", context={})


@router.get("/bulk", response_class=HTMLResponse)
async def bulk_page(request: Request):
    """Bulk analysis page — analyse all enabled rules."""
    templates = get_templates()
    return templates.TemplateResponse(request, "bulk.html", context={})
