"""History, bulk analysis, and scheduled rules API routes."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("sda.web")
router = APIRouter(prefix="/api", tags=["history"])


# ── Analysis History ──────────────────────────────────────────────────────

@router.get("/history")
async def api_history(
    page: int = 1, per_page: int = 20,
    search: str = "", verdict: str = "",
    sort_by: str = "created_at", sort_order: str = "desc",
):
    """API: List past analyses with pagination and filtering."""
    from sda.db import list_analyses
    return await list_analyses(
        page=page, per_page=per_page, search=search,
        verdict=verdict, sort_by=sort_by, sort_order=sort_order,
    )


@router.get("/history/{analysis_id}")
async def api_history_detail(analysis_id: str):
    """API: Get a specific past analysis by ID."""
    from sda.db import get_analysis
    report = await get_analysis(analysis_id)
    if not report:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    return report


@router.delete("/history/{analysis_id}")
async def api_history_delete(analysis_id: str):
    """API: Delete an analysis."""
    from sda.db import delete_analysis
    deleted = await delete_analysis(analysis_id)
    return {"deleted": deleted}


# ── Bulk Analysis ─────────────────────────────────────────────────────────

@router.post("/bulk/start")
async def api_bulk_start(request: Request):
    """API: Start a bulk analysis of multiple rules."""
    data = await request.json()
    rule_ids = data.get("rule_ids", [])
    max_concurrent = data.get("max_concurrent", 2)

    from sda.bulk import start_bulk_analysis
    run_id = await start_bulk_analysis(
        rule_ids=rule_ids or None, max_concurrent=max_concurrent,
    )
    if not run_id:
        return JSONResponse(
            status_code=400, content={"error": "No rules found to analyse"}
        )
    return {"run_id": run_id, "status": "started"}


@router.get("/bulk/status/{run_id}")
async def api_bulk_status(run_id: str):
    """API: Get status of a bulk analysis run."""
    from sda.bulk import get_bulk_status
    status = get_bulk_status(run_id)
    if status is None:
        return JSONResponse(status_code=404, content={"error": "Run not found"})
    return status


# ── Scheduled Rules ───────────────────────────────────────────────────────

@router.get("/scheduled")
async def api_scheduled_list():
    """API: List scheduled rules."""
    from sda.db import list_scheduled_rules
    return await list_scheduled_rules()


@router.post("/scheduled")
async def api_scheduled_add(request: Request):
    """API: Add a rule to the schedule."""
    data = await request.json()
    from sda.db import save_scheduled_rule
    await save_scheduled_rule(
        rule_name=data.get("rule_name", ""),
        rule_source=data.get("rule_source", ""),
        rule_content=data.get("rule_content", ""),
        schedule_cron=data.get("schedule_cron", "0 2 * * 1"),
    )
    return {"status": "scheduled"}
