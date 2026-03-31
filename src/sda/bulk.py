"""Bulk analysis — analyse multiple rules in one batch.

Fetches all enabled rules from Kibana and runs analysis on each,
ranking results by noise level.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# In-memory state for active bulk runs
_bulk_runs: dict[str, dict] = {}


async def start_bulk_analysis(
    rule_ids: list[str] | None = None,
    max_concurrent: int = 2,
) -> str:
    """Start a bulk analysis job.

    Args:
        rule_ids: Specific rule IDs to analyse. If empty, fetches all enabled rules.
        max_concurrent: Max concurrent analyses.

    Returns:
        Bulk run ID for status tracking.
    """
    from sda.kibana_client import list_detection_rules
    from sda.config import get_config

    config = get_config()
    run_id = f"bulk-{uuid.uuid4().hex[:8]}"

    # Fetch rules
    if rule_ids:
        rules_resp = list_detection_rules(cfg=config.es)
        all_rules = rules_resp.get("data", [])
        rules = [r for r in all_rules if r.get("id") in rule_ids]
    else:
        rules_resp = list_detection_rules(cfg=config.es)
        rules = [r for r in rules_resp.get("data", []) if r.get("enabled")]

    if not rules:
        return ""

    _bulk_runs[run_id] = {
        "id": run_id,
        "status": "running",
        "total": len(rules),
        "completed": 0,
        "failed": 0,
        "results": [],
        "started_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    # Launch in background
    asyncio.create_task(_run_bulk(run_id, rules, max_concurrent))
    return run_id


async def _run_bulk(run_id: str, rules: list[dict], max_concurrent: int) -> None:
    """Execute bulk analysis with concurrency control."""
    from sda.agent.orchestrator import run_analysis

    semaphore = asyncio.Semaphore(max_concurrent)
    run = _bulk_runs[run_id]

    async def _analyse_one(rule: dict) -> dict:
        async with semaphore:
            rule_name = rule.get("name", "Unknown")
            start = time.time()
            try:
                # Build minimal rule content for the analyser
                rule_content = _rule_to_content(rule)
                report = await run_analysis(rule_content, "elastic")
                result = {
                    "rule_name": rule_name,
                    "rule_id": rule.get("id", ""),
                    "verdict": str(report.verdict.value) if hasattr(report.verdict, 'value') else str(report.verdict),
                    "noise_hits": report.noise_hits,
                    "actual_alerts": report.actual_alert_count,
                    "fpr": report.fpr,
                    "alerts_per_day": report.estimated_alerts_per_day,
                    "severity": rule.get("severity", ""),
                    "duration": round(time.time() - start, 1),
                    "status": "done",
                }
                run["completed"] += 1

                # Persist individual result
                try:
                    from sda.db import save_analysis
                    analysis_id = f"bulk-{uuid.uuid4().hex[:8]}"
                    report_dict = report.model_dump(mode="json")
                    report_dict["analysis_id"] = analysis_id
                    report_dict["source"] = "bulk"
                    await save_analysis(analysis_id, report_dict)
                except Exception:
                    pass

                return result
            except Exception as exc:
                run["failed"] += 1
                return {
                    "rule_name": rule_name,
                    "rule_id": rule.get("id", ""),
                    "verdict": "error",
                    "error": str(exc),
                    "duration": round(time.time() - start, 1),
                    "status": "error",
                }

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rules.sort(key=lambda r: severity_order.get(r.get("severity", "medium"), 2))

    # Run all with controlled concurrency
    tasks = [_analyse_one(r) for r in rules]
    results = await asyncio.gather(*tasks)

    run["results"] = sorted(results, key=lambda r: r.get("alerts_per_day", 0), reverse=True)
    run["status"] = "done"
    run["completed_at"] = datetime.now(tz=timezone.utc).isoformat()

    logger.info("Bulk analysis %s complete: %d/%d rules analysed (%d failed)",
                run_id, run["completed"], run["total"], run["failed"])


def get_bulk_status(run_id: str) -> dict | None:
    """Get status of a bulk analysis run."""
    return _bulk_runs.get(run_id)


def _rule_to_content(rule: dict) -> str:
    """Convert a Kibana rule dict to TOML-like content for the analyser."""
    import json
    return json.dumps(rule, indent=2)
