"""Analysis API routes — submit, poll, and delete analyses."""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
import uuid

from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import JSONResponse
from starlette.responses import RedirectResponse

from sda.web.dependencies import (
    analyses, get_templates, test_es_connection, MAX_CONTENT_LEN,
)

logger = logging.getLogger("sda.web")
router = APIRouter(tags=["analysis"])


@router.post("/analyse")
async def analyse(
    request: Request,
    rule_content: str = Form(""),
    rule_file: UploadFile | None = File(None),
    format_hint: str = Form("auto"),
    lookback_days: int = Form(7),
    index_override: str = Form(""),
):
    """Submit a rule for analysis — runs in background, redirects immediately."""
    templates = get_templates()
    content = rule_content
    if rule_file and rule_file.filename:
        content = (await rule_file.read()).decode("utf-8")

    if not content.strip():
        from sda.config import get_config
        es_status = test_es_connection()
        return templates.TemplateResponse(
            request, "index.html",
            context={
                "error": "Please provide a rule (paste or upload).",
                "analyses": list(analyses.values()),
                "es_connected": es_status.get("connected", False),
                "config": get_config(),
            },
        )

    # Enforce content size limit
    if len(content) > MAX_CONTENT_LEN:
        from sda.config import get_config
        es_status = test_es_connection()
        return templates.TemplateResponse(
            request, "index.html",
            context={
                "error": f"Rule content too large ({len(content):,} bytes). Maximum is {MAX_CONTENT_LEN:,} bytes.",
                "analyses": list(analyses.values()),
                "es_connected": es_status.get("connected", False),
                "config": get_config(),
            },
        )

    # Apply index override if provided
    index_override = index_override.strip()
    if index_override:
        try:
            rule_data = json.loads(content)
            rule_data["index"] = [i.strip() for i in index_override.split(",")]
            content = json.dumps(rule_data, indent=2)
            logger.info("Index override applied: %s", rule_data["index"])
        except (json.JSONDecodeError, TypeError):
            pass

    analysis_id = f"sda-{uuid.uuid4().hex[:12]}"

    analyses[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "running",
        "rule_name": "Analysing...",
    }

    async def _run_in_background():
        try:
            from sda.config import get_config, update_config
            if lookback_days and lookback_days != 7:
                update_config(**{"es.noise_lookback_days": lookback_days})

            logger.info(
                "[%s] Starting analysis — format=%s, content_size=%d bytes",
                analysis_id, format_hint, len(content),
            )

            from sda.agent.orchestrator import run_analysis
            report = await run_analysis(content, format_hint)
            logger.info(
                "[%s] Analysis complete — verdict=%s, noise_hits=%d, duration=%.1fs",
                analysis_id, report.verdict, report.noise_hits,
                report.analysis_duration_seconds,
            )

            result = report.model_dump(mode="json")
            result["analysis_id"] = analysis_id
            result["status"] = "done"
            analyses[analysis_id] = result

            try:
                from sda.db import save_analysis
                await save_analysis(analysis_id, result)
            except Exception as db_exc:
                logger.warning("Failed to save analysis to DB: %s", db_exc)

        except Exception as exc:
            logger.error(
                "[%s] Analysis FAILED: %s\n%s",
                analysis_id, exc, traceback.format_exc(),
            )
            try:
                from sda.parsers.elastic_parser import parse_elastic_rule
                rule = parse_elastic_rule(content)
                analyses[analysis_id] = {
                    "analysis_id": analysis_id,
                    "rule_name": rule.name or "Unknown",
                    "error": str(exc),
                    "verdict": "error",
                    "status": "done",
                }
            except Exception as parse_exc:
                analyses[analysis_id] = {
                    "analysis_id": analysis_id,
                    "error": f"Parse error: {parse_exc}. Analysis error: {exc}",
                    "verdict": "error",
                    "status": "done",
                }

    asyncio.create_task(_run_in_background())
    logger.info("[%s] Background task started, redirecting to report page", analysis_id)
    return RedirectResponse(url=f"/report/{analysis_id}", status_code=303)


@router.get("/api/status/{analysis_id}")
async def api_status(analysis_id: str):
    """Poll endpoint: returns analysis status as JSON."""
    entry = analyses.get(analysis_id)
    if not entry:
        return {"status": "not_found"}
    return {"status": entry.get("status", "done")}


@router.delete("/api/analysis/{analysis_id}")
async def api_delete_analysis(analysis_id: str):
    """Delete an analysis from the store."""
    if analysis_id in analyses:
        del analyses[analysis_id]
        return {"deleted": True}
    return JSONResponse({"error": "Analysis not found"}, status_code=404)


# ── JSON API endpoints (for React frontend) ──────────────────────────────


@router.post("/api/analyse")
async def api_analyse(request: Request):
    """JSON API: Submit a rule for analysis — returns analysis_id immediately."""
    data = await request.json()
    content = data.get("rule_content", "").strip()
    format_hint = data.get("format_hint", "auto")
    lookback_days = data.get("lookback_days", 7)
    index_override = data.get("index_override", "").strip()

    if not content:
        return JSONResponse({"error": "rule_content is required"}, status_code=400)

    if len(content) > MAX_CONTENT_LEN:
        return JSONResponse(
            {"error": f"Rule content too large ({len(content):,} bytes). Max: {MAX_CONTENT_LEN:,}"},
            status_code=400,
        )

    # Apply index override
    if index_override:
        try:
            rule_data = json.loads(content)
            rule_data["index"] = [i.strip() for i in index_override.split(",")]
            content = json.dumps(rule_data, indent=2)
        except (json.JSONDecodeError, TypeError):
            pass

    analysis_id = f"sda-{uuid.uuid4().hex[:12]}"
    analyses[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "running",
        "rule_name": "Analysing...",
    }

    async def _run():
        try:
            from sda.config import get_config, update_config
            if lookback_days and lookback_days != 7:
                update_config(**{"es.noise_lookback_days": lookback_days})
            from sda.agent.orchestrator import run_analysis
            report = await run_analysis(content, format_hint)
            result = report.model_dump(mode="json")
            result["analysis_id"] = analysis_id
            result["status"] = "done"
            analyses[analysis_id] = result
            try:
                from sda.db import save_analysis
                await save_analysis(analysis_id, result)
            except Exception:
                pass
        except Exception as exc:
            analyses[analysis_id] = {
                "analysis_id": analysis_id,
                "error": str(exc),
                "verdict": "error",
                "status": "done",
            }

    asyncio.create_task(_run())
    return {"analysis_id": analysis_id, "status": "running"}


@router.get("/api/analysis/{analysis_id}")
async def api_get_analysis(analysis_id: str):
    """JSON API: Get full analysis data from the in-memory store."""
    entry = analyses.get(analysis_id)
    if not entry:
        # Try DB fallback
        try:
            from sda.db import get_analysis
            db_entry = await get_analysis(analysis_id)
            if db_entry:
                db_entry["status"] = "done"
                return db_entry
        except Exception:
            pass
        return JSONResponse({"error": "Analysis not found"}, status_code=404)
    return entry

