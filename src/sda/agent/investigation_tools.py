"""Investigation tools — agent-callable functions for Phase 2 FP analysis.

These tools let the LLM autonomously investigate noise hit patterns
by querying Elasticsearch for aggregations and drill-down documents.
The agent decides which ECS fields to investigate based on rule typology.

Thread-safe: context is passed via PydanticAI's deps injection, not module globals.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from pydantic_ai import RunContext

from sda.config import ElasticsearchConfig, get_config
from sda.engine.executor import aggregate_fields, drill_down, get_field_mapping

logger = logging.getLogger(__name__)


# ─── State container for investigation context ────────────────────────────────

class InvestigationContext:
    """Holds the context for an ongoing investigation.

    Passed to the agent via PydanticAI's deps_type so each concurrent
    analysis has its own isolated context.
    """

    MAX_TOOL_CALLS = 20  # prevent runaway LLM loops

    def __init__(
        self,
        index_pattern: str,
        base_query: dict,
        time_start: datetime,
        time_end: datetime,
        cfg: ElasticsearchConfig,
    ):
        self.index_pattern = index_pattern
        self.base_query = base_query
        self.time_start = time_start
        self.time_end = time_end
        self.cfg = cfg
        self._tool_call_count = 0
        self._field_cache: str | None = None  # cached get_fields result

    def check_budget(self) -> None:
        """Increment tool call counter and raise if budget exceeded."""
        self._tool_call_count += 1
        if self._tool_call_count > self.MAX_TOOL_CALLS:
            raise RuntimeError(
                f"Tool call budget exceeded ({self.MAX_TOOL_CALLS} calls). "
                "Produce your final output now."
            )


# ─── Agent-callable tools ─────────────────────────────────────────────────────


def investigate_aggregate(
    ctx: RunContext[InvestigationContext],
    fields: list[str],
    top_n: int = 25,
) -> str:
    """Aggregate the noise hits by the specified ECS fields.

    Choose fields relevant to the rule type:
    - Process rules: process.name, process.parent.name, process.command_line, user.name
    - Network rules: source.ip, destination.ip, destination.port, network.protocol
    - Auth rules: user.name, source.ip, event.outcome, event.action
    - File rules: file.path, file.name, process.name, user.name

    You can aggregate 1-4 fields at once. Multi-field aggregation shows
    the top combinations (e.g. process.name + user.name pairs).

    Args:
        ctx: Run context with investigation dependencies (injected automatically).
        fields: List of ECS field names to aggregate (1-4 fields).
        top_n: Number of top results to return (default 25).

    Returns:
        JSON string with the top value combinations and their doc_count.
    """
    inv = ctx.deps
    inv.check_budget()

    if not fields or len(fields) > 4:
        return json.dumps({"error": "Provide 1-4 field names to aggregate"})

    results = aggregate_fields(
        index_pattern=inv.index_pattern,
        base_query=inv.base_query,
        fields=fields,
        time_start=inv.time_start,
        time_end=inv.time_end,
        top_n=top_n,
        cfg=inv.cfg,
    )

    return json.dumps({
        "fields": fields,
        "total_buckets": len(results),
        "buckets": results,
    }, indent=2, default=str)


def investigate_drill_down(
    ctx: RunContext[InvestigationContext],
    filters: dict[str, str],
    size: int = 5,
) -> str:
    """Fetch full ECS documents matching the rule query + extra field filters.

    Use this AFTER aggregation to see the complete context of a specific pattern.
    The returned documents contain ALL ECS fields, not just the aggregated ones.

    Args:
        ctx: Run context with investigation dependencies (injected automatically).
        filters: Dict of field→value to filter on (e.g. {"process.name": "svchost.exe"}).
        size: Number of documents to return (max 10).

    Returns:
        JSON string with full _source documents.
    """
    inv = ctx.deps
    inv.check_budget()

    if not filters:
        return json.dumps({"error": "Provide at least one field filter"})

    docs = drill_down(
        index_pattern=inv.index_pattern,
        base_query=inv.base_query,
        filters=filters,
        time_start=inv.time_start,
        time_end=inv.time_end,
        size=min(size, 10),
        cfg=inv.cfg,
    )

    return json.dumps({
        "filters_applied": filters,
        "documents_returned": len(docs),
        "documents": docs,
    }, indent=2, default=str, ensure_ascii=False)


def investigate_get_fields(
    ctx: RunContext[InvestigationContext],
) -> str:
    """List the available ECS fields in the target index.

    Use this to discover which fields exist before aggregating.
    Only returns fields usable for aggregation (keyword, ip, long, boolean).

    Args:
        ctx: Run context with investigation dependencies (injected automatically).

    Returns:
        JSON string with field names and their ES types.
    """
    inv = ctx.deps
    inv.check_budget()

    # Return cached result if available (field mappings don't change mid-analysis)
    if inv._field_cache is not None:
        return inv._field_cache

    fields = get_field_mapping(
        index_pattern=inv.index_pattern,
        cfg=inv.cfg,
    )

    # Group by ECS category for better readability
    grouped: dict[str, list[str]] = {}
    for field_name in sorted(fields.keys()):
        category = field_name.split(".")[0] if "." in field_name else "_root"
        grouped.setdefault(category, []).append(field_name)

    result = json.dumps({
        "total_fields": len(fields),
        "fields_by_category": grouped,
    }, indent=2)

    inv._field_cache = result
    return result


def investigate_simulate_exclusion(
    ctx: RunContext[InvestigationContext],
    exclusions: dict[str, str],
) -> str:
    """Simulate what happens if you add an exclusion — returns remaining match count.

    Takes a dict of field→value pairs that would be added as a rule exception
    (must_not clauses). Returns the count of remaining matches after the
    exclusion is applied, so you can report the predicted alert reduction.

    Call this AFTER identifying a pattern to report the post-exclusion count.

    Args:
        ctx: Run context with investigation dependencies (injected automatically).
        exclusions: Dict of field→value to exclude (e.g. {"host.hostname": "server01", "process.name": "sudo"}).

    Returns:
        JSON with original_count, remaining_count, and reduction_pct.
    """
    inv = ctx.deps
    inv.check_budget()

    if not exclusions:
        return json.dumps({"error": "Provide at least one field→value exclusion"})

    from sda.engine.executor import _get_es_client

    es = _get_es_client(inv.cfg)

    try:
        # Build must_not clauses from exclusions
        must_not_clauses = []
        for field, value in exclusions.items():
            if "," in value:
                for v in value.split(","):
                    must_not_clauses.append({"match_phrase": {field: v.strip()}})
            else:
                must_not_clauses.append({"match_phrase": {field: value}})

        # Count original matches
        original_body = deepcopy(inv.base_query)
        if "query" not in original_body:
            original_body = {"query": original_body}

        time_filter = {"range": {"@timestamp": {
            "gte": inv.time_start.isoformat(),
            "lte": inv.time_end.isoformat(),
        }}}

        # Original count
        orig_query = deepcopy(original_body)
        orig_inner = orig_query.get("query", {})
        if "bool" not in orig_inner:
            orig_inner = {"bool": {"must": [orig_inner]}}
            orig_query["query"] = orig_inner
        orig_inner.setdefault("bool", {}).setdefault("must", []).append(time_filter)

        # Strip fields that _count API doesn't support
        for key in ("size", "aggs", "sort", "_source", "fields", "from"):
            orig_query.pop(key, None)

        orig_resp = es.count(index=inv.index_pattern, body=orig_query)
        original_count = orig_resp.get("count", 0)

        # Count with exclusions applied
        excl_query = deepcopy(orig_query)
        excl_bool = excl_query["query"].setdefault("bool", {})
        existing_mn = excl_bool.get("must_not", [])
        if isinstance(existing_mn, dict):
            existing_mn = [existing_mn]
        excl_bool["must_not"] = existing_mn + must_not_clauses

        excl_resp = es.count(index=inv.index_pattern, body=excl_query)
        remaining_count = excl_resp.get("count", 0)

        removed = original_count - remaining_count
        pct = (removed / original_count * 100) if original_count > 0 else 0

        return json.dumps({
            "exclusions_applied": exclusions,
            "original_matches": original_count,
            "remaining_matches": remaining_count,
            "matches_removed": removed,
            "reduction_pct": round(pct, 1),
        }, indent=2)

    except Exception as exc:
        logger.warning("Simulate exclusion failed: %s", exc)
        return json.dumps({"error": str(exc)})
    finally:
        es.close()
