"""PydanticAI agent orchestrator — detection rule analysis & FP investigation.

Pipeline:
  Phase 1 (deterministic): Parse → ES query → Differential metrics
  Phase 2 (agentic):       LLM investigates noise hits with ES tools → FP recommendations

The Phase 2 agent gets investigation tools (aggregate_fields, drill_down,
get_field_mapping) and autonomously decides which ECS fields to investigate
based on the rule typology.
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

from pydantic_ai import Agent

from sda.config import AppConfig, LLMConfig, get_config
from sda.models.report import ImpactReport

logger = logging.getLogger(__name__)

# Kibana alert metadata fields to strip from sample alerts before sending to LLM
KIBANA_NOISE_PREFIXES = (
    "kibana.alert.rule.parameters", "kibana.alert.rule.execution",
    "kibana.alert.uuid", "kibana.alert.start", "kibana.alert.end",
    "kibana.alert.time_range", "kibana.alert.flapping",
    "kibana.alert.consecutive_matches", "kibana.alert.maintenance_window",
    "kibana.alert.instance.id", "kibana.alert.duration",
    "kibana.alert.last_detected", "kibana.space_ids",
    "kibana.version", "event.kind",
)

# ─── Investigation System Prompt ──────────────────────────────────────────────

INVESTIGATION_PROMPT = """\
You are a Senior SOC Detection Engineer performing false-positive triage on an \
Elastic Security rule. You have Elasticsearch tools to investigate the noise.

## Investigation Strategy

1. **Read the rule** — understand what activity it detects.
2. **Discover fields** — call `investigate_get_fields` to see available ECS fields.
3. **Composite aggregation first** — use `investigate_aggregate_fields` with 2-3 \
key fields simultaneously (e.g. process.parent.name + process.name, or user.name + url.domain) \
to find recurring patterns fast. Don't aggregate one field at a time.
4. **Drill down** — for each high-frequency pattern, call `investigate_drill_down` \
to get full ECS documents with all field context.
5. **Consolidate** — group similar patterns into the fewest possible exceptions. \
See the Consolidation Strategy below.
6. **Simulate exclusion** — for each consolidated pattern, call \
`investigate_simulate_exclusion` with the proposed exception fields. Call it \
CUMULATIVELY: include ALL prior exclusion fields in each subsequent call so \
you can report the running predicted alert total.
7. **Decide** — for each consolidated pattern, assign a verdict and risk score.

## Consolidation Strategy (CRITICAL)

Your goal is to produce the FEWEST exceptions that cover the MOST noise. Follow these rules:

- **NEVER create per-host exceptions when a process-based exception covers the same behavior.** \
If hosts A, B, and C all run `nodeagent > sudo > monitor.sh`, that is ONE pattern \
with ONE exception on `process.parent.name: nodeagent`, NOT three host-specific exceptions.
- **Prefer behavioral fields** (process.parent.name, process.name, process.command_line, \
user.name, url.domain) over infrastructure fields (host.hostname, host.ip).
- **Use host.hostname ONLY when** the activity is truly unique to that host and cannot \
be described by process lineage or user identity.
- **Merge patterns** that share the same process tree / parent-child relationship even \
if the exact command arguments differ slightly.
- **Use match_any** when a single field has multiple related values \
(e.g. process.parent.name: sudo,nodeagent,timeout for the same monitoring workflow).

## Output Format (STRICT — follow exactly)

For each CONSOLIDATED pattern, output EXACTLY this structure:

---

### Pattern N — [one-line description of the behavioral pattern]

| Field | Detail |
|---|---|
| Verdict | **EXCLUDE** or **REVIEW** or **KEEP** |
| Confidence | High / Medium / Low |
| Risk Score | N/10 |
| Frequency | N hits (N% of noise) |
| Hosts | N hosts |
| Affected hosts | host1, host2, ... |

**Key indicators:**

| ECS Field | Value |
|---|---|
| process.executable | value |
| process.parent.executable | value |
| user.name | value |

**Assessment:** [2-3 concise sentences explaining your analytical reasoning]

**Impact:** Predicted alerts drop from N to M (-X%) — *cumulative, includes all prior exclusions*

**Recommendation:** [one sentence: what the SOC team should do with this pattern]

```json
{
  "entries": [
    {"field": "field.name.text", "operator": "included", "type": "match", "value": "exact_value"},
    {"field": "field.name.text", "operator": "included", "type": "match_any", "value": "val1,val2"}
  ]
}
```

---

After ALL patterns, end with:

### Triage Summary

| Metric | Value |
|---|---|
| Total noise analyzed | N alerts |
| Patterns identified | N |
| Recommended exclusions | N |
| Requires review | N |
| Keep alerting | N |
| Noise reduction (if all applied) | N% |
| Predicted remaining alerts | N (from N) |
| Estimated remaining FPR | N% |

---

## Strict Rules

### Analysis Quality
- Be CONCISE. Max 3 sentences per assessment.
- Every EXCLUDE pattern MUST have the JSON exception block.
- REVIEW patterns: include the JSON but explicitly state what validation is needed.
- KEEP patterns: no JSON needed, explain why this should remain alerting.
- NEVER propose single-field exceptions. Always combine 2+ fields.
- NEVER create separate exceptions for the same behavior on different hosts — CONSOLIDATE.
- If unsure whether something is FP, verdict is REVIEW, not EXCLUDE.
- Do NOT repeat investigation methodology or general advice.
- Do NOT add a separate "recommendations" section — per-pattern verdicts ARE the recommendations.
- The "Impact" line MUST be CUMULATIVE — show the running total after ALL prior exclusions.

### Markdown Formatting (CRITICAL)
- NEVER use unclosed backticks. Every opening backtick MUST have a matching closing backtick.
- In tables, do NOT use backticks around values. Write field values as plain text.
- Use **bold** (double asterisks) for emphasis, not backticks.
- Ensure all table rows have the exact same number of pipe characters.
- Use `---` horizontal rules between patterns to ensure proper separation.
- JSON code blocks MUST use triple backticks with the json language tag.

### Exception JSON Rules
- **Each pattern's JSON block is INDEPENDENT.** Only entries for THAT pattern. \
Do NOT copy entries from previous patterns into subsequent JSON blocks.
- **The cumulative tracking is ONLY for the "Impact" text line**, NOT for the JSON entries.
- **Always use .text suffix for keyword exception fields:** \
process.executable.text, process.parent.executable.text, process.name.text, \
process.command_line.text, file.path.text, url.domain.text, etc.
- **Exception for non-text fields:** user.name, host.hostname, host.name, event.action, \
event.category, process.code_signature.subject_name do NOT need the .text suffix.
"""


def _build_model(config: AppConfig):
    """Build the pydantic-ai model for OpenAI-compatible or Anthropic endpoint."""
    llm_cfg = config.llm

    if not (llm_cfg.base_url and llm_cfg.api_key):
        return f"openai:{llm_cfg.deployment_name}"

    if llm_cfg.provider == "anthropic":
        try:
            from pydantic_ai.models.anthropic import AnthropicModel
            from pydantic_ai.providers.anthropic import AnthropicProvider

            has_custom_url = llm_cfg.base_url and llm_cfg.base_url != LLMConfig().base_url

            if has_custom_url:
                # Use AnthropicFoundry for custom endpoints (Azure, etc.)
                try:
                    from anthropic import AsyncAnthropicFoundry
                    client = AsyncAnthropicFoundry(
                        api_key=llm_cfg.api_key,
                        base_url=llm_cfg.base_url,
                    )
                except ImportError:
                    # Older SDK — fall back to AsyncAnthropic with base_url
                    from anthropic import AsyncAnthropic
                    client = AsyncAnthropic(
                        api_key=llm_cfg.api_key,
                        base_url=llm_cfg.base_url,
                    )
            else:
                from anthropic import AsyncAnthropic
                client = AsyncAnthropic(api_key=llm_cfg.api_key)

            provider = AnthropicProvider(anthropic_client=client)
            return AnthropicModel(llm_cfg.deployment_name, provider=provider)
        except Exception as exc:
            logger.warning("Failed to create Anthropic model: %s", exc)
            return f"anthropic:{llm_cfg.deployment_name}"
    else:
        try:
            from openai import AsyncOpenAI
            from pydantic_ai.models.openai import OpenAIModel
            from pydantic_ai.providers.openai import OpenAIProvider

            base = llm_cfg.base_url.rstrip("/")
            if not base.endswith("/v1"):
                base += "/v1"

            is_standard_openai = "api.openai.com" in base
            if is_standard_openai:
                # Standard OpenAI API — use api_key directly (Bearer auth)
                async_client = AsyncOpenAI(
                    base_url=base,
                    api_key=llm_cfg.api_key,
                )
            else:
                # Azure / custom OpenAI-compatible — use api-key header
                async_client = AsyncOpenAI(
                    base_url=base,
                    api_key="unused",
                    default_headers={"api-key": llm_cfg.api_key},
                )
            provider = OpenAIProvider(openai_client=async_client)
            return OpenAIModel(llm_cfg.deployment_name, provider=provider)
        except Exception as exc:
            logger.warning("Failed to create OpenAI model: %s", exc)
            return f"openai:{llm_cfg.deployment_name}"


def _create_investigation_agent(config: AppConfig) -> Agent:
    """Create the Phase 2 investigation agent with ES-backed tools.

    Uses PydanticAI deps_type for thread-safe context injection —
    each concurrent analysis gets its own InvestigationContext.
    """
    from sda.agent.investigation_tools import (
        InvestigationContext,
        investigate_aggregate,
        investigate_drill_down,
        investigate_get_fields,
        investigate_simulate_exclusion,
    )

    model = _build_model(config)

    ag = Agent(
        model,
        system_prompt=INVESTIGATION_PROMPT,
        deps_type=InvestigationContext,
        retries=2,
    )

    # Register investigation tools (use .tool() for RunContext injection)
    ag.tool(investigate_aggregate)
    ag.tool(investigate_drill_down)
    ag.tool(investigate_get_fields)
    ag.tool(investigate_simulate_exclusion)

    return ag


def _create_behavioral_agent(config: AppConfig) -> Agent:
    """Create a toolless agent for behavioral rule triage.

    Behavioral (Elastic Defend) rules can't be queried directly — the agent
    analyses sample alert data embedded in the prompt without ES tools.
    """
    model = _build_model(config)
    return Agent(model, system_prompt=INVESTIGATION_PROMPT)


# ─── Analysis Pipeline ────────────────────────────────────────────────────────


def _extract_fpr_from_ai(ai_text: str) -> float | None:
    """Extract overall FPR from AI triage output text.

    Priority order (most reliable → least reliable):
      1. Noise reduction % = overall FPR (98.4% noise reduction = 98.4% of all alerts are FP)
      2. Explicit FP Rate % (old prompt format)

    NOTE: "Estimated remaining FPR" is NOT used because it measures FPR within
    the residual alerts after all exclusions (e.g. 59% of 227 remaining alerts),
    not the overall FPR of the full alert set.

    Returns:
        FPR as a float (0.0-1.0), or None if not found.
    """
    if not ai_text:
        return None

    # 1. Noise reduction % = overall FPR (most reliable)
    # "Noise reduction (if all applied) | 98.4%" means 98.4% of all alerts are FP
    nr_patterns = [
        r'Noise reduction\s*\([^)]*\)\s*\|\s*(\d+(?:\.\d+)?)\s*%',
        r'Cumulative noise reduction\s*\|\s*(\d+(?:\.\d+)?)\s*%',
    ]
    for pattern in nr_patterns:
        match = re.search(pattern, ai_text, re.IGNORECASE)
        if match:
            return float(match.group(1)) / 100.0

    # 2. Legacy explicit FP Rate (old prompt format)
    fp_match = re.search(
        r'Estimated FP Rate\s*\|\s*(\d+(?:\.\d+)?)\s*%', ai_text, re.IGNORECASE
    )
    if fp_match:
        return float(fp_match.group(1)) / 100.0

    return None


def _extract_remaining_alerts_from_ai(ai_text: str) -> int | None:
    """Extract predicted remaining alert count from AI triage output.

    Looks for patterns like:
      - Predicted remaining alerts | 227 (from 14010)
      - Predicted remaining alerts | 227

    Returns:
        The predicted remaining alert count, or None if not found.
    """
    if not ai_text:
        return None

    match = re.search(
        r'Predicted remaining alerts\s*\|\s*(\d[\d,]*)',
        ai_text, re.IGNORECASE,
    )
    if match:
        return int(match.group(1).replace(",", ""))
    return None


async def run_analysis(
    rule_content: str,
    format_hint: str = "auto",
    config: AppConfig | None = None,
) -> ImpactReport:
    """Run the full detection rule analysis pipeline.

    Strategy: deterministic pipeline first (fast, reliable), then optionally
    enhance the report with agentic FP investigation.

    Args:
        rule_content: Raw rule text (Sigma YAML or Elastic JSON).
        format_hint: Format hint — 'sigma', 'elastic', or 'auto'.
        config: Optional config override.

    Returns:
        A completed ImpactReport.
    """
    if config is None:
        config = get_config()

    analysis_id = f"sda-{uuid.uuid4().hex[:12]}"
    start_time = time.time()

    # ── Phase 1: Deterministic analysis (always runs) ─────────────────────
    # Run in thread pool to avoid blocking the event loop (keeps /api/health alive)
    import asyncio

    def _run_phase1():
        import json as _json
        from sda.engine.differential import calculate_differential
        from sda.engine.executor import execute_rule
        from sda.models.rule import CandidateRule

        logger.info("Phase 1.1: Parsing rule (format=%s)...", format_hint)
        from sda.parsers.elastic_parser import parse_elastic_rule as _parse_rule
        rule_dict = _parse_rule(rule_content).model_dump()
        rule = CandidateRule.model_validate(rule_dict)
        logger.info("Phase 1.2: Rule parsed — name='%s', type=%s, indices=%s",
                     rule.name, rule.rule_type, rule.target_indices)

        # Extract rule's lookback period from the 'from' field (e.g. 'now-360h')
        # Use max(rule_from, noise_lookback_days) — the rule's 'from' is the scheduling
        # window, but for noise analysis we need at least noise_lookback_days
        rule_json_raw = _json.loads(rule_content)
        rule_from = rule_json_raw.get("from", "")
        lookback_days = config.es.noise_lookback_days
        if rule_from:
            import re as _re
            m = _re.search(r'now-(\d+)([hdms])', rule_from)
            if m:
                val, unit = int(m.group(1)), m.group(2)
                rule_days = lookback_days  # default
                if unit == 'h':
                    rule_days = max(val // 24, 1)
                elif unit == 'd':
                    rule_days = val
                elif unit == 'm':
                    rule_days = max(val // (24 * 60), 1)
                elif unit == 's':
                    rule_days = 1
                # Always use at least noise_lookback_days for analysis
                lookback_days = max(rule_days, config.es.noise_lookback_days)
                logger.info("Phase 1.2: Lookback: rule from='%s' (%dd), using %dd for analysis",
                             rule_from, rule_days, lookback_days)

        # ── Phase 1.2b: Resolve data_view_id to actual index pattern ──────
        dv_tag = next((t for t in rule.tags if t.startswith("__data_view_id:")), None)
        if dv_tag and config.es.kibana_url:
            dv_id = dv_tag.split(":", 1)[1]
            from sda.kibana_client import resolve_data_view
            resolved = resolve_data_view(dv_id, cfg=config.es)
            if resolved:
                old_indices = rule.target_indices
                rule = rule.model_copy(update={
                    "target_indices": [p.strip() for p in resolved.split(",")],
                    "tags": [t for t in rule.tags if not t.startswith("__data_view_id:")],
                })
                logger.info("Phase 1.2b: Resolved data_view '%s' → %s (was %s)",
                             dv_id, rule.target_indices, old_indices)

        # ── Phase 1.3: Fetch and apply existing rule exceptions ───────────
        # This ensures the analysis query matches what ES Security runs in prod
        try:
            rule_json = _json.loads(rule_content)
            exceptions_list = rule_json.get("exceptions_list", [])
            if exceptions_list and config.es.kibana_url:
                logger.info("Phase 1.3: Fetching %d exception list(s) from Kibana...",
                             len(exceptions_list))
                from sda.kibana_client import fetch_rule_exceptions
                must_not_clauses = fetch_rule_exceptions(rule_json, cfg=config.es)

                if must_not_clauses:
                    logger.info("Phase 1.3: Applying %d must_not clauses from exceptions",
                                 len(must_not_clauses))
                    # Merge must_not into the query
                    query = rule.es_query.copy()
                    if "query" in query:
                        inner = query["query"]
                        if "bool" not in inner:
                            inner = {"bool": {"must": [inner]}}
                            query["query"] = inner
                        inner_bool = inner.setdefault("bool", {})
                        existing = inner_bool.get("must_not", [])
                        if isinstance(existing, dict):
                            existing = [existing]
                        inner_bool["must_not"] = existing + must_not_clauses
                    rule = rule.model_copy(update={"es_query": query})
                    logger.info("Phase 1.3: Exceptions applied — query updated with %d exclusions",
                                 len(must_not_clauses))
                else:
                    logger.info("Phase 1.3: No exception clauses to apply")
            else:
                logger.info("Phase 1.3: No exception lists on this rule (or Kibana not configured)")
        except Exception as exc:
            logger.warning("Phase 1.3: Failed to fetch/apply exceptions (non-blocking): %s", exc)

        # Log the translated query for debugging
        logger.info("Phase 1.4: Executing query against ES (lookback=%dd)...", lookback_days)
        import json as _json2
        q_str = _json2.dumps(rule.es_query.get('query', {}), default=str)[:500]
        logger.info("Phase 1.4: Query DSL: %s", q_str)
        noise_result = execute_rule(rule, cfg=config.es, days=lookback_days)
        logger.info("Phase 1.5: ES query done — %d hits, took %dms",
                     noise_result.total_hits, noise_result.took_ms)

        logger.info("Phase 1.6: Computing differential report...")
        report = calculate_differential(
            rule=rule,
            noise_result=noise_result,
            analysis_id=analysis_id,
            cfg=config,
        )
        logger.info("Phase 1.7: Report computed — verdict=%s", report.verdict)
        report.rule_type = rule.rule_type
        report.severity = rule.severity
        report.target_indices = rule.target_indices

        # ── Phase 1.8: Get actual + predicted alert count ────────────────
        is_behavioral = False
        try:
            rule_json = _json.loads(rule_content)
        except Exception:
            rule_json = {}

        from sda.engine.executor import count_actual_alerts, predict_deduplicated_alerts

        # ── Detect Elastic Defend envelope/behavioral rules ──
        # Envelope rules (Malicious File, Memory Threat, Ransomware, Behavior
        # Detected/Prevented) just forward Elastic Agent alerts to Kibana.
        # Running their query against telemetry is meaningless — they should
        # be analyzed via actual Kibana alerts + AI triage.
        _ENVELOPE_PATTERNS = [
            "behavior - detected", "behavior - prevented",
            "malicious file - detected", "malicious file - prevented",
            "memory threat - detected", "memory threat - prevented",
            "ransomware - detected", "ransomware - prevented",
            "endpoint security",
        ]
        rule_name_lower = rule.name.lower()
        is_envelope = any(p in rule_name_lower for p in _ENVELOPE_PATTERNS)

        # Also check if the rule targets endpoint alerts index
        if not is_envelope:
            is_envelope = any("logs-endpoint.alerts" in idx for idx in rule.target_indices)

        is_behavioral = (
            is_envelope
            or rule_json.get("_metadata", {}).get("source") == "behavioral"
            or rule_json.get("_behavioral") is not None
            or noise_result.query_used.get("_endpoint_only", False)
        )

        if is_envelope:
            logger.info("Phase 1.8: Envelope rule detected ('%s') — "
                         "raw query results are meaningless, using actual alerts only",
                         rule.name)

        # 1) Query ACTUAL alerts (ground truth)
        if is_behavioral:
            logger.info("Phase 1.8a: Behavioral rule — querying actual alerts from "
                         "logs-endpoint.alerts-* + .alerts-security.alerts-*...")
        else:
            logger.info("Phase 1.8a: Querying actual alerts from .alerts-security.alerts-*...")
        # Extract rule UUID for fallback alert matching
        rule_uuid = rule_json.get("id", "")

        alerts_data = count_actual_alerts(rule.name, cfg=config.es, rule_uuid=rule_uuid)
        if alerts_data["alert_count"] >= 0:
            report.actual_alert_count = alerts_data["alert_count"]
            report.sample_alerts = alerts_data.get("sample_alerts", [])
            report.alert_distributions = alerts_data.get("distributions", {})
            logger.info("Phase 1.8a: Actual alerts = %d", alerts_data["alert_count"])
        else:
            logger.warning("Phase 1.8a: Could not query alerts index")

        # 2) Run suppression prediction — skip when actual data is sufficient
        #    - Behavioral rules: always skip (Elastic Defend is always active)
        #    - SIEM rules active > 7 days: skip (actual alerts are ground truth)
        #    - SIEM rules disabled or < 7 days old: run prediction as fallback
        rule_enabled = rule_json.get("enabled", False)
        rule_created = rule_json.get("created_at", "")
        rule_age_days = -1
        if rule_created:
            try:
                created_dt = datetime.fromisoformat(rule_created.replace("Z", "+00:00"))
                rule_age_days = (datetime.now(timezone.utc) - created_dt).days
            except Exception:
                pass

        skip_prediction = False
        skip_reason = ""

        if is_behavioral:
            skip_prediction = True
            skip_reason = "behavioral rule — Elastic Defend is always active"
        elif rule_enabled and rule_age_days > 7:
            skip_prediction = True
            skip_reason = (f"rule active for {rule_age_days} days — "
                           "actual alerts are ground truth, prediction unnecessary")
        elif rule_enabled and rule_age_days >= 0:
            skip_reason = f"rule active but only {rule_age_days} days old — prediction needed"
        elif not rule_enabled:
            skip_reason = "rule is disabled — prediction needed for impact estimate"

        if skip_prediction:
            logger.info("Phase 1.8b: Skipping suppression prediction (%s)", skip_reason)
            prediction = {"predicted_alerts": -1, "suppression_fields": [], "method": f"skipped_{skip_reason[:30]}"}
        else:
            logger.info("Phase 1.8b: Running suppression prediction (%s)", skip_reason)
            prediction = predict_deduplicated_alerts(rule, rule_json, cfg=config.es)

            # 2b) Craft synthetic alert documents for AI analysis
            #     Groups raw hits by suppression fields → one alert per unique group
            from sda.engine.executor import craft_predicted_alerts
            logger.info("Phase 1.8c: Crafting predicted alert documents...")
            crafted = craft_predicted_alerts(rule, rule_json, cfg=config.es)
            if crafted.get("alerts"):
                # Replace raw samples with crafted synthetic alerts
                # Each alert = {group_key, hit_count, representative_doc, latest_timestamp}
                report.sample_alerts = crafted["alerts"]
                report.predicted_alert_count = crafted["total_groups"]
                logger.info("Phase 1.8c: Crafted %d synthetic alerts from %d raw hits "
                             "(grouped by %s)",
                             crafted["total_groups"],
                             crafted.get("total_raw_hits", 0),
                             crafted["group_by_fields"])
            else:
                logger.info("Phase 1.8c: Could not craft alerts (method=%s), "
                             "AI will use raw samples", crafted.get("method", "unknown"))

        report.suppression_fields = prediction.get("suppression_fields", [])
        report.suppression_method = prediction.get("method", "")
        report.suppression_duration = prediction.get("duration", "")

        if prediction["predicted_alerts"] >= 0:
            report.predicted_alert_count = prediction["predicted_alerts"]
            logger.info("Phase 1.8b: Predicted alerts = %d (method=%s, fields=%s)",
                         prediction["predicted_alerts"], prediction["method"],
                         prediction.get("suppression_fields", []))

        # 3) Recalculate alert rate using the most accurate source
        # - Behavioral rules: ONLY actual alerts
        # - SIEM rules active > 7d: ONLY actual alerts (prediction skipped)
        # - SIEM rules disabled/new: Prefer actual > prediction > raw hits
        if is_behavioral or (rule_enabled and rule_age_days > 7):
            best_count = max(report.actual_alert_count, 0)
            count_source = "actual_only"
        else:
            best_count = report.actual_alert_count if report.actual_alert_count >= 0 else (
                prediction["predicted_alerts"] if prediction["predicted_alerts"] >= 0 else noise_result.total_hits
            )
            count_source = "actual" if report.actual_alert_count >= 0 else (
                "predicted" if prediction["predicted_alerts"] >= 0 else "raw_hits"
            )
        lookback_hours = config.es.noise_lookback_days * 24
        report.estimated_alerts_per_hour = best_count / max(lookback_hours, 1)
        report.estimated_alerts_per_day = report.estimated_alerts_per_hour * 24

        # For behavioral rules, defer FPR/verdict to AFTER Phase 2 AI analysis
        # (the AI triage determines what % of alerts are false positives)
        if is_behavioral and best_count > 0:
            report.noise_hits = best_count
            report.is_behavioral = True
            logger.info("Phase 1.8: Behavioral rule — FPR deferred to Phase 2 AI triage")

        logger.info("Phase 1.8: Summary — actual=%d, predicted=%d, raw=%d → using %d (%s) "
                     "[enabled=%s, age=%dd%s]",
                     report.actual_alert_count,
                     prediction.get("predicted_alerts", -1),
                     noise_result.total_hits,
                     best_count, count_source,
                     rule_enabled, rule_age_days,
                     " (behavioral)" if is_behavioral else "")

        return rule, noise_result, report, is_behavioral

    rule, noise_result, report, is_behavioral = await asyncio.to_thread(_run_phase1)

    logger.info(
        "Phase 1 complete: %s — %d hits, FPR=%.4f, verdict=%s (%.1fs)",
        rule.name, report.noise_hits, report.fpr,
        report.verdict, time.time() - start_time,
    )

    # ── Phase 2: Agentic FP investigation (optional, best-effort) ─────────
    # Skip for very low hit counts (not worth AI investigation cost)
    MIN_HITS_FOR_AI = 1
    AI_TIMEOUT_SECONDS = config.llm.agent_timeout

    has_data_to_investigate = (report.noise_hits >= MIN_HITS_FOR_AI
                               or report.actual_alert_count > 0)

    # Skip Phase 2 for behavioral rules using tools — we can't run the EQL directly.
    # BUT if we have sample alerts from Kibana, we can still run AI analysis
    # by feeding the alert documents directly into the prompt (no tools needed).
    # Re-evaluate behavioral flag — if raw query returned 0 hits but actual
    # Kibana alerts exist, the rule is effectively behavioral (EQL may have
    # failed or only works inside the Elastic Agent)
    if not is_behavioral and report.noise_hits == 0 and report.actual_alert_count > 0:
        is_behavioral = True
        logger.info("Phase 2: Rule reclassified as behavioral (0 raw hits, %d actual alerts)",
                     report.actual_alert_count)
    if is_behavioral and report.sample_alerts:
        logger.info("Phase 2: Behavioral rule — using %d sample alerts for AI investigation",
                     len(report.sample_alerts))
        # Run a simpler AI investigation using sample alert data directly
        if config.llm.base_url and config.llm.api_key:
            try:
                simple_agent = _create_behavioral_agent(config)

                # Build a summary of the sample alerts — include all ECS fields
                # but filter out noisy Kibana internal metadata
                alert_summaries = []
                for i, alert in enumerate(report.sample_alerts[:10], 1):
                    # Handle crafted synthetic alerts (from craft_predicted_alerts)
                    if "representative_doc" in alert:
                        group = alert.get("group_key", {})
                        hits = alert.get("hit_count", 0)
                        doc = alert.get("representative_doc", {})
                        clean = {k: v for k, v in doc.items()
                                 if not k.startswith(KIBANA_NOISE_PREFIXES)}
                        fields_str = json.dumps(clean, indent=2, default=str)
                        if len(fields_str) > 6000:
                            fields_str = fields_str[:6000] + "\n  ... (truncated)"
                        group_str = ", ".join(f"{k}={v}" for k, v in group.items())
                        alert_summaries.append(
                            f"### Predicted Alert Group {i} — {hits:,} raw hits\n"
                            f"**Grouping**: {group_str}\n"
                            f"```json\n{fields_str}\n```"
                        )
                    else:
                        # Regular Kibana alert (flat ECS dict)
                        clean = {k: v for k, v in alert.items()
                                 if not k.startswith(KIBANA_NOISE_PREFIXES)}
                        fields_str = json.dumps(clean, indent=2, default=str)
                        if len(fields_str) > 6000:
                            fields_str = fields_str[:6000] + "\n  ... (truncated)"
                        alert_summaries.append(f"### Alert {i}\n```json\n{fields_str}\n```")

                alerts_block = "\n\n".join(alert_summaries)

                # Build field distribution summary from aggregations
                dist_lines = []
                if report.alert_distributions:
                    for field, buckets in report.alert_distributions.items():
                        dist_lines.append(f"### {field}")
                        for entry in buckets[:10]:
                            dist_lines.append(
                                f"- `{entry['value']}` — {entry['count']:,} alerts ({entry['pct']}%)"
                            )
                dist_block = "\n".join(dist_lines) if dist_lines else "No distributions available."

                user_prompt = f"""\
Investigate and triage the alerts for this Elastic Defend behavioral rule. Analyze the field distributions (computed across ALL {report.actual_alert_count} alerts) and the sample alert data to identify false positive patterns and produce exception recommendations.

**Rule**: {rule.name} ({rule.rule_type}, {rule.severity})
**Total alerts**: {report.actual_alert_count} in last {config.es.noise_lookback_days} days
**Alert rate**: {report.estimated_alerts_per_day:.1f}/day

## Field Distributions (across ALL {report.actual_alert_count} alerts)

{dist_block}

## Sample Alert Data ({len(report.sample_alerts)} most recent)

{alerts_block}

IMPORTANT:
- The FIELD DISTRIBUTIONS above cover ALL {report.actual_alert_count} alerts — use these for frequency analysis and pattern identification.
- The SAMPLE ALERTS provide detailed ECS context (process paths, command lines, code signatures) for the most recent events.
- Combine both to identify false positive patterns (e.g., "99% of alerts from host X running process Y").
- Produce exception recommendations with KQL-compatible JSON entries.
- Frequency percentages MUST be based on the distributions (all alerts), not just the {len(report.sample_alerts)} samples.
"""
                ai_result = await asyncio.wait_for(
                    simple_agent.run(user_prompt),
                    timeout=AI_TIMEOUT_SECONDS,
                )
                ai_output = ai_result.output

                # Track token usage
                try:
                    usage = ai_result.usage()
                    report.ai_tokens_used = usage.total_tokens or 0
                    logger.info("Phase 2 tokens (behavioral): input=%d, output=%d, total=%d",
                                usage.request_tokens or 0, usage.response_tokens or 0,
                                usage.total_tokens or 0)
                except Exception:
                    pass

                if isinstance(ai_output, str) and ai_output.strip():
                    report.recommendations = [ai_output]
                elif isinstance(ai_output, list):
                    report.recommendations = [str(r) for r in ai_output]

                logger.info(
                    "Phase 2 complete: Behavioral AI analysis added %d recommendations (%.1fs)",
                    len(report.recommendations), time.time() - start_time,
                )

                # ── Extract FPR from AI triage output ──
                # Parse various FPR/noise-reduction patterns from the triage summary
                ai_text = report.recommendations[0] if report.recommendations else ""
                fp_rate = _extract_fpr_from_ai(ai_text)

                if fp_rate is not None and is_behavioral:
                    from sda.engine.differential import determine_verdict
                    from sda.models.report import Verdict
                    report.fpr = fp_rate
                    fp_alerts = int(report.actual_alert_count * fp_rate)
                    tp_alerts = report.actual_alert_count - fp_alerts
                    verdict, reason = determine_verdict(
                        fpr=fp_rate,
                        noise_hits=report.actual_alert_count,
                        alerts_per_day=report.estimated_alerts_per_day,
                        cfg=config,
                    )

                    # Check if AI found actionable exclusions that would reduce noise
                    remaining = _extract_remaining_alerts_from_ai(ai_text)
                    if verdict == Verdict.REJECT and remaining is not None:
                        reduction_pct = (1 - remaining / max(report.actual_alert_count, 1)) * 100
                        if reduction_pct >= 50:  # AI found exclusions reducing ≥50% of noise
                            verdict = Verdict.TUNE
                            reason = (
                                f"FPR ({fp_rate:.2%}) exceeds threshold, but AI identified exclusions that would "
                                f"reduce alerts from {report.actual_alert_count:,} to {remaining:,} "
                                f"(-{reduction_pct:.0f}%). Apply recommended exclusions and re-analyse."
                            )

                    report.verdict = verdict
                    report.verdict_reason = (
                        f"AI triage: {fp_rate:.0%} of {report.actual_alert_count:,} alerts are false positives "
                        f"({fp_alerts:,} FP, {tp_alerts:,} TP). "
                        f"~{report.estimated_alerts_per_day:.0f} alerts/day. {reason}"
                    )
                    logger.info(
                        "Phase 2: AI-derived FPR=%.2f (%d FP / %d total), verdict=%s",
                        fp_rate, fp_alerts, report.actual_alert_count, verdict,
                    )
            except asyncio.TimeoutError:
                logger.warning("Phase 2 timed out after %ds — skipping AI investigation", AI_TIMEOUT_SECONDS)
            except Exception as exc:
                logger.warning("Phase 2 (behavioral AI analysis) skipped: %s", exc)
        else:
            logger.info("Phase 2 skipped: LLM not configured")
        has_data_to_investigate = False  # Don't run tool-based Phase 2
    elif is_behavioral:
        has_data_to_investigate = False
        logger.info("Phase 2 skipped: behavioral rule with no sample alerts")

    if config.llm.base_url and config.llm.api_key and has_data_to_investigate:
        try:
            from sda.agent.investigation_tools import InvestigationContext

            # Build investigation context — passed as deps (thread-safe)
            now = datetime.now(tz=timezone.utc)
            ctx = InvestigationContext(
                index_pattern=noise_result.index_pattern or config.es.production_indices,
                base_query=rule.es_query,
                time_start=now - timedelta(days=config.es.noise_lookback_days),
                time_end=now,
                cfg=config.es,
            )
            logger.info("Phase 2: Investigating predicted alerts from %s", ctx.index_pattern)

            # Create the investigation agent
            agent = _create_investigation_agent(config)

            # Build the user prompt with analysis summary
            actual = report.actual_alert_count
            predicted = report.predicted_alert_count
            alert_count = predicted if predicted > 0 else (actual if actual >= 0 else report.noise_hits)
            suppression_info = ""
            if report.suppression_fields:
                suppression_info = f"\n| Suppression fields | {', '.join(report.suppression_fields)} |"
                suppression_info += f"\n| Suppression window | {report.suppression_duration} |"

            # Threshold rule guidance — alerts only have metadata, not source events
            threshold_guidance = ""
            if rule.rule_type in ("threshold", "new_terms"):
                threshold_guidance = f"""
CRITICAL — THRESHOLD/AGGREGATE RULE:
- Alert documents ONLY contain threshold metadata (count, grouping fields like user.name).
- They do NOT contain the underlying source events (URLs, domains, processes, etc.).
- You MUST use `investigate_aggregate_fields` and `investigate_drill_down` on the SOURCE INDEX ({noise_result.index_pattern or config.es.production_indices}) to find the actual events behind each threshold breach.
- For example, if the threshold groups by user.name, drill down into each user's events to find the specific URLs/domains/processes that triggered the rule.
- Do NOT base your entire analysis on the alert metadata alone — it tells you WHO triggered the threshold, not WHAT they did.
"""

            # Build actual alert context if available
            actual_alerts_block = ""
            if report.sample_alerts:
                KIBANA_NOISE_PREFIXES_TUPLE = KIBANA_NOISE_PREFIXES
                sample_summaries = []
                is_crafted = any("representative_doc" in a for a in report.sample_alerts[:5])
                for i, alert in enumerate(report.sample_alerts[:5], 1):
                    if "representative_doc" in alert:
                        group = alert.get("group_key", {})
                        hits = alert.get("hit_count", 0)
                        doc = alert.get("representative_doc", {})
                        clean = {k: v for k, v in doc.items()
                                 if not k.startswith(KIBANA_NOISE_PREFIXES_TUPLE)}
                        fields_str = json.dumps(clean, indent=2, default=str)
                        if len(fields_str) > 4000:
                            fields_str = fields_str[:4000] + "\n  ... (truncated)"
                        group_str = ", ".join(f"{k}={v}" for k, v in group.items())
                        sample_summaries.append(
                            f"### Predicted Alert Group {i} — {hits:,} raw hits\n"
                            f"**Grouping**: {group_str}\n"
                            f"```json\n{fields_str}\n```"
                        )
                    else:
                        clean = {k: v for k, v in alert.items()
                                 if not k.startswith(KIBANA_NOISE_PREFIXES_TUPLE)}
                        fields_str = json.dumps(clean, indent=2, default=str)
                        if len(fields_str) > 4000:
                            fields_str = fields_str[:4000] + "\n  ... (truncated)"
                        sample_summaries.append(f"### Alert {i}\n```json\n{fields_str}\n```")

                dist_lines = []
                if report.alert_distributions:
                    for field, buckets in report.alert_distributions.items():
                        dist_lines.append(f"### {field}")
                        for entry in buckets[:10]:
                            dist_lines.append(
                                f"- `{entry['value']}` — {entry['count']:,} alerts ({entry['pct']}%)"
                            )
                dist_block = "\n".join(dist_lines) if dist_lines else ""

                if is_crafted:
                    alert_label = f"Predicted Alert Groups ({len(report.sample_alerts)} unique groups from raw telemetry)"
                    alert_context = (
                        "These are PREDICTED alerts — the rule is disabled/new, so these represent "
                        "what Kibana WOULD generate if the rule were active. Each group = one deduplicated alert."
                    )
                else:
                    alert_label = f"Actual Production Alerts ({report.actual_alert_count} total from Kibana)"
                    alert_context = (
                        "These are the REAL alerts that fired in production. "
                        "Cross-reference these with your source index investigation."
                    )

                actual_alerts_block = f"""
## {alert_label}

{alert_context}

### Field Distributions (across all alerts)
{dist_block if dist_block else "No distributions available."}

### Sample Alert Documents ({len(report.sample_alerts[:5])} most recent)
{"".join(sample_summaries)}
"""

            user_prompt = f"""\
Investigate and triage the predicted alerts for this rule. Use your tools, then output patterns in the required format.

**Rule**: {rule.name} ({rule.rule_type}, {rule.severity})
**Index**: {noise_result.index_pattern or config.es.production_indices}
**Predicted alerts**: {alert_count}

| Metric | Count |
|--------|-------|
| Predicted alerts | {predicted if predicted > 0 else 'N/A'} |
| Actual alerts in production | {actual if actual >= 0 else 'N/A'} |
| Raw query matches | {report.noise_hits} |
| Lookback period | {config.es.noise_lookback_days} days |{suppression_info}
{threshold_guidance}{actual_alerts_block}
IMPORTANT:
- You are investigating the events behind {alert_count} PREDICTED ALERTS.
- The predicted alerts are derived from {report.noise_hits} raw matches, grouped by suppression fields over time windows.
- Start your aggregation with the suppression fields ({', '.join(report.suppression_fields) if report.suppression_fields else 'rule-dependent'}) combined with other context fields.
- Use `top_n=25` to surface ALL distinct patterns.
- Frequency percentages must be relative to {alert_count} predicted alerts, NOT {report.noise_hits} raw matches.
- Investigate ALL predicted alerts — do not stop after the top 3 patterns.
{f"- Cross-reference your findings with the {report.actual_alert_count} actual production alerts shown above." if report.sample_alerts else ""}
"""
            # Run AI with timeout to avoid blocking forever
            # Pass ctx as deps for thread-safe tool access
            ai_result = await asyncio.wait_for(
                agent.run(user_prompt, deps=ctx),
                timeout=AI_TIMEOUT_SECONDS,
            )
            ai_output = ai_result.output

            # Track token usage
            try:
                usage = ai_result.usage()
                report.ai_tokens_used += usage.total_tokens or 0
                logger.info("Phase 2 tokens (tools): input=%d, output=%d, total=%d",
                            usage.request_tokens or 0, usage.response_tokens or 0,
                            usage.total_tokens or 0)
            except Exception:
                pass

            if isinstance(ai_output, str) and ai_output.strip():
                report.recommendations = [ai_output]
            elif isinstance(ai_output, list):
                report.recommendations = [str(r) for r in ai_output]
            elif isinstance(ai_output, dict):
                report.recommendations = [json.dumps(ai_output, indent=2)]

            logger.info(
                "Phase 2 complete: AI FP investigation added %d recommendations (%.1fs)",
                len(report.recommendations), time.time() - start_time,
            )

            # ── Extract FPR from AI triage for non-behavioral rules too ──
            ai_text = report.recommendations[0] if report.recommendations else ""
            fp_rate = _extract_fpr_from_ai(ai_text)
            if fp_rate is not None:
                from sda.engine.differential import determine_verdict
                from sda.models.report import Verdict
                report.fpr = fp_rate
                alert_total = report.actual_alert_count if report.actual_alert_count > 0 else report.noise_hits
                fp_alerts = int(alert_total * fp_rate)
                tp_alerts = alert_total - fp_alerts
                verdict, reason = determine_verdict(
                    fpr=fp_rate,
                    noise_hits=alert_total,
                    alerts_per_day=report.estimated_alerts_per_day,
                    cfg=config,
                )

                # Check if AI found actionable exclusions that would reduce noise
                remaining = _extract_remaining_alerts_from_ai(ai_text)
                if verdict == Verdict.REJECT and remaining is not None:
                    reduction_pct = (1 - remaining / max(alert_total, 1)) * 100
                    if reduction_pct >= 50:
                        verdict = Verdict.TUNE
                        reason = (
                            f"FPR ({fp_rate:.2%}) exceeds threshold, but AI identified exclusions that would "
                            f"reduce alerts from {alert_total:,} to {remaining:,} "
                            f"(-{reduction_pct:.0f}%). Apply recommended exclusions and re-analyse."
                        )

                report.verdict = verdict
                report.verdict_reason = (
                    f"AI triage: {fp_rate:.0%} of {alert_total:,} alerts are false positives "
                    f"({fp_alerts:,} FP, {tp_alerts:,} TP). "
                    f"~{report.estimated_alerts_per_day:.0f} alerts/day. {reason}"
                )
                logger.info(
                    "Phase 2: AI-derived FPR=%.2f (%d FP / %d total), verdict=%s",
                    fp_rate, fp_alerts, alert_total, verdict,
                )
        except asyncio.TimeoutError:
            logger.warning("Phase 2 timed out after %ds — skipping AI investigation", AI_TIMEOUT_SECONDS)
        except Exception as exc:
            logger.warning("Phase 2 (AI investigation) skipped: %s", exc)
    elif report.noise_hits > 0 and report.noise_hits < MIN_HITS_FOR_AI:
        logger.info("Phase 2 skipped: only %d hits (threshold: %d)", report.noise_hits, MIN_HITS_FOR_AI)
    elif report.noise_hits == 0:
        logger.info("Phase 2 skipped: no noise hits to investigate")

    report.analysis_duration_seconds = time.time() - start_time
    return report

