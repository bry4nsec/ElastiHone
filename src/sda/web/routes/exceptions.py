"""Exception API routes — apply exceptions to Kibana."""

from __future__ import annotations

import json
import logging
import re

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("sda.web")
router = APIRouter(prefix="/api", tags=["exceptions"])


@router.post("/exception/apply")
async def api_exception_apply(request: Request):
    """API: Push an exception directly to Kibana."""
    data = await request.json()
    rule_name = data.get("rule_name", "")
    rule_id = data.get("rule_id", "")
    entries = data.get("entries", [])
    analysis_id = data.get("analysis_id", "")

    if not entries:
        return JSONResponse(
            status_code=400, content={"error": "No entries provided"}
        )

    from sda.kibana_client import apply_exception
    result = apply_exception(
        rule_id=rule_id, rule_name=rule_name, entries=entries,
    )

    if result.get("status") == "applied":
        try:
            from sda.db import save_exception
            await save_exception(
                analysis_id=analysis_id,
                rule_name=rule_name,
                kql_query=" AND ".join(
                    f'{e["field"]}: "{e["value"]}"' for e in entries
                ),
                entries_json=json.dumps(entries),
                kibana_list_id=result.get("list_id", ""),
                status="applied",
            )
        except Exception as exc:
            logger.warning("Failed to save exception to DB: %s", exc)

    return result


@router.post("/exception/apply-recommended")
async def api_exception_apply_recommended(request: Request):
    """API: Apply selected exception entries to Kibana.

    Each entry group (one exclusion pattern) becomes a SEPARATE exception item.
    """
    data = await request.json()
    rule_name = data.get("rule_name", "")
    rule_id = data.get("rule_id", "")
    analysis_id = data.get("analysis_id", "")
    pre_parsed_entries = data.get("entries", [])
    recommendations = data.get("recommendations", [])

    # Build list of entry GROUPS — each group = one exception item
    entry_groups: list[list[dict]] = []

    if pre_parsed_entries:
        for entry_group in pre_parsed_entries:
            if isinstance(entry_group, list):
                # Already a group of entries — keep together
                valid = [e for e in entry_group if isinstance(e, dict) and e.get("field") and e.get("value")]
                if valid:
                    entry_groups.append(valid)
            elif isinstance(entry_group, dict) and entry_group.get("field"):
                # Single entry — wrap as its own group
                entry_groups.append([entry_group])
    elif recommendations:
        for rec_text in recommendations:
            if not isinstance(rec_text, str):
                continue
            json_blocks = re.findall(
                r'\{[^{}]*"entries"\s*:\s*\[.*?\]\s*\}', rec_text, re.DOTALL
            )
            for block in json_blocks:
                try:
                    parsed = json.loads(block)
                    entries = [e for e in parsed.get("entries", []) if e.get("field") and e.get("value")]
                    if entries:
                        entry_groups.append(entries)
                except json.JSONDecodeError:
                    continue

    if not entry_groups:
        return JSONResponse(status_code=400, content={
            "error": "No exception entries found",
            "status": "no_entries",
        })

    try:
        from sda.kibana_client import apply_exception

        results = []
        for i, group in enumerate(entry_groups, 1):
            result = apply_exception(
                rule_id=rule_id,
                rule_name=rule_name,
                entries=group,
                exception_item_name=f"ElastiHone exclusion {i} for {rule_name}",
            )
            results.append(result)

        # Save to DB
        all_entries_flat = [e for g in entry_groups for e in g]
        success_count = sum(1 for r in results if r.get("status") == "applied")
        first_result = results[0] if results else {}

        if success_count > 0:
            try:
                from sda.db import save_exception
                await save_exception(
                    analysis_id=analysis_id,
                    rule_name=rule_name,
                    kql_query=" AND ".join(
                        f'{e["field"]}: "{e.get("value", "")}"'
                        for e in all_entries_flat[:5]
                    ),
                    entries_json=json.dumps(entry_groups),
                    kibana_list_id=first_result.get("list_id", ""),
                    status="applied",
                )
            except Exception as exc:
                logger.warning("Failed to save exception to DB: %s", exc)

        return {
            "status": "applied" if success_count > 0 else "failed",
            "list_id": first_result.get("list_id", ""),
            "items_created": success_count,
            "items_total": len(entry_groups),
            "rule_linked": first_result.get("rule_linked", False),
            "message": f"Created {success_count}/{len(entry_groups)} exception items in Kibana",
        }

    except Exception as exc:
        logger.error("Failed to apply recommended exceptions: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"error": str(exc), "status": "failed"},
        )


@router.get("/exceptions")
async def api_exceptions_list(rule_name: str = ""):
    """API: List applied exceptions."""
    from sda.db import list_exceptions
    return await list_exceptions(rule_name=rule_name)
