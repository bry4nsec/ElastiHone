"""Differential calculator — computes TPR, FPR, verdict, alert rate, and cost analysis."""

from __future__ import annotations

import re
import json
import logging

from sda.config import AppConfig, get_config
from sda.models.report import CostAnalysis, CostLevel, ImpactReport, Verdict
from sda.models.rule import CandidateRule
from sda.models.telemetry import SearchResult

logger = logging.getLogger(__name__)


def calculate_tpr(signal_result: SearchResult | None = None) -> float:
    """True Positive Rate = detected attacks / total injected attacks.
    Returns 0.0 if no signal analysis was performed.
    """
    if signal_result is None or signal_result.total_docs == 0:
        return 0.0
    return min(signal_result.total_hits / signal_result.total_docs, 1.0)


def calculate_fpr(noise_result: SearchResult) -> float:
    """False Positive Rate = noise matches / total production events."""
    if noise_result.total_docs == 0:
        return 0.0
    return min(noise_result.total_hits / noise_result.total_docs, 1.0)


def calculate_alert_rate(noise_result: SearchResult, days: int = 7) -> tuple[float, float]:
    """Estimate alert rate from noise results.

    Returns:
        Tuple of (alerts_per_hour, alerts_per_day).
    """
    if days <= 0:
        return 0.0, 0.0

    alerts_per_day = noise_result.total_hits / days
    alerts_per_hour = alerts_per_day / 24.0
    return alerts_per_hour, alerts_per_day


def calculate_cost(rule: CandidateRule) -> CostAnalysis:
    """Estimate computational cost of a rule based on query complexity.

    Analyses the query structure for expensive operations:
    - Wildcards (leading wildcards are expensive)
    - Regex patterns
    - Nested aggregations
    - EQL sequences / joins
    - Large query depth
    """
    query_str = json.dumps(rule.es_query)

    # Feature extraction
    has_wildcards = "*" in query_str
    leading_wildcards = len(re.findall(r'"\*[^"]+', query_str))
    has_regex = bool(re.search(r'"regexp"', query_str))
    has_nested_aggs = query_str.count('"aggs"') > 1 or query_str.count('"aggregations"') > 1
    has_joins = "sequence" in query_str.lower() or "join" in query_str.lower()
    query_depth = query_str.count("{")
    has_script = '"script"' in query_str

    # Scoring (0-100)
    score = 10  # Base
    score += min(leading_wildcards * 15, 30)  # Leading wildcards are very expensive
    score += 10 if has_wildcards else 0
    score += 15 if has_regex else 0
    score += 20 if has_nested_aggs else 0
    score += 20 if has_joins else 0
    score += min(query_depth * 2, 20)
    score += 15 if has_script else 0
    score = min(score, 100)

    # Classify
    if score <= 25:
        level = CostLevel.LOW
        cpu_pct = 0.01
    elif score <= 50:
        level = CostLevel.MEDIUM
        cpu_pct = 0.05
    elif score <= 75:
        level = CostLevel.HIGH
        cpu_pct = 0.15
    else:
        level = CostLevel.CRITICAL
        cpu_pct = 0.35

    notes_parts: list[str] = []
    if leading_wildcards:
        notes_parts.append(f"{leading_wildcards} leading wildcard(s) — expensive on large indices")
    if has_regex:
        notes_parts.append("Contains regex — CPU-intensive on keyword fields")
    if has_joins:
        notes_parts.append("EQL sequence/join — requires correlation engine memory")
    if has_script:
        notes_parts.append("Scripted field — disables query cache")
    if has_nested_aggs:
        notes_parts.append("Nested aggregations — high memory usage")

    return CostAnalysis(
        level=level,
        query_complexity_score=score,
        has_wildcards=has_wildcards,
        has_regex=has_regex,
        has_nested_aggregations=has_nested_aggs,
        has_joins=has_joins,
        estimated_cpu_pct_per_execution=cpu_pct,
        notes="; ".join(notes_parts) if notes_parts else "Standard query complexity",
    )


def determine_verdict(
    fpr: float,
    noise_hits: int = 0,
    alerts_per_day: float = 0.0,
    tpr: float = 0.0,
    cfg: AppConfig | None = None,
) -> tuple[Verdict, str]:
    """Determine the verdict based on noise analysis.

    In noise-only mode (no signal), verdict is based on FPR and alert rate.
    If TPR is available (signal was used), both are considered.

    Returns:
        Tuple of (verdict, reason).
    """
    if cfg is None:
        cfg = get_config()

    # If we have TPR data, use combined logic
    if tpr > 0:
        if tpr >= cfg.approve_tpr_min and fpr < cfg.approve_fpr_max:
            return (
                Verdict.APPROVE,
                f"TPR ({tpr:.1%}) ≥ {cfg.approve_tpr_min:.0%} and FPR ({fpr:.2%}) < {cfg.approve_fpr_max:.0%}. "
                f"Rule is effective with minimal noise.",
            )
        if tpr >= cfg.review_tpr_min and fpr < cfg.review_fpr_max:
            return (
                Verdict.REVIEW,
                f"TPR ({tpr:.1%}) is acceptable but FPR ({fpr:.2%}) approaches threshold. "
                f"Consider adding exclusions before deployment.",
            )

    # Noise-only verdict
    if fpr < cfg.approve_fpr_max:
        return (
            Verdict.APPROVE,
            f"FPR ({fpr:.2%}) < {cfg.approve_fpr_max:.0%} — "
            f"{noise_hits} matches, ~{alerts_per_day:.0f} alerts/day. Acceptable noise level.",
        )

    if fpr < cfg.review_fpr_max:
        return (
            Verdict.REVIEW,
            f"FPR ({fpr:.2%}) — {noise_hits} matches, ~{alerts_per_day:.0f} alerts/day. "
            f"Consider adding exclusions to reduce noise before deployment.",
        )

    return (
        Verdict.REJECT,
        f"FPR ({fpr:.2%}) exceeds {cfg.review_fpr_max:.0%} — "
        f"{noise_hits} matches, ~{alerts_per_day:.0f} alerts/day. "
        f"Rule generates too much noise. Requires fine-tuning before deployment.",
    )


def build_recommendations(
    tpr: float,
    fpr: float,
    cost: CostAnalysis,
    noise_result: SearchResult,
) -> list[str]:
    """Generate actionable recommendations based on analysis results."""
    recs: list[str] = []

    # Noise recommendations
    if fpr >= 0.05:
        recs.append(
            "HIGH NOISE: Rule matches >5% of production events. "
            "Add exception clauses for known-good processes, signed binaries, or internal IPs."
        )
        if noise_result.sample_hits:
            common_processes = _extract_common_values(noise_result.sample_hits, "process.name")
            if common_processes:
                recs.append(
                    f"Consider excluding these frequently-matched processes: "
                    f"{', '.join(common_processes[:5])}"
                )
    elif fpr >= 0.01:
        recs.append(
            "MODERATE NOISE: FPR between 1-5%. Review false positives and add targeted exclusions."
        )

    # Cost recommendations
    if cost.level in (CostLevel.HIGH, CostLevel.CRITICAL):
        recs.append(
            f"PERFORMANCE: Query complexity is {cost.level.value}. "
            f"{cost.notes}"
        )

    if not recs:
        recs.append("Rule passes all quality checks. Ready for production deployment.")

    return recs


def _extract_common_values(docs: list[dict], field: str, top_n: int = 5) -> list[str]:
    """Extract the most common values for a dotted field path from sample documents."""
    from collections import Counter

    values: list[str] = []
    for doc in docs:
        val = _get_nested(doc, field)
        if val and isinstance(val, str):
            values.append(val)
    counter = Counter(values)
    return [v for v, _ in counter.most_common(top_n)]


def _get_nested(doc: dict, path: str):
    """Get a value from a nested dict using a dotted path."""
    parts = path.split(".")
    current = doc
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def calculate_differential(
    rule: CandidateRule,
    noise_result: SearchResult,
    signal_result: SearchResult | None = None,
    days: int = 7,
    analysis_id: str = "",
    cfg: AppConfig | None = None,
) -> ImpactReport:
    """Calculate the full differential impact report.

    Works in noise-only mode by default. Signal analysis is optional.

    Args:
        rule: The candidate rule being analysed.
        noise_result: Results from noise (production) dataset.
        signal_result: Optional results from signal dataset.
        days: Lookback window used for noise analysis.
        analysis_id: Unique identifier for this analysis run.
        cfg: Optional config override.

    Returns:
        Complete ImpactReport with verdict, metrics, and recommendations.
    """
    if cfg is None:
        cfg = get_config()

    tpr = calculate_tpr(signal_result)
    fpr = calculate_fpr(noise_result)
    alerts_per_hour, alerts_per_day = calculate_alert_rate(noise_result, days)
    cost = calculate_cost(rule)
    verdict, verdict_reason = determine_verdict(
        fpr=fpr,
        noise_hits=noise_result.total_hits,
        alerts_per_day=alerts_per_day,
        tpr=tpr,
        cfg=cfg,
    )
    recommendations = build_recommendations(tpr, fpr, cost, noise_result)

    return ImpactReport(
        rule_id=rule.id,
        rule_name=rule.name,
        analysis_id=analysis_id or f"sda-{rule.fingerprint}",
        verdict=verdict,
        verdict_reason=verdict_reason,
        tpr=tpr,
        signal_hits=signal_result.total_hits if signal_result else 0,
        signal_total=signal_result.total_docs if signal_result else 0,
        fpr=fpr,
        noise_hits=noise_result.total_hits,
        noise_total=noise_result.total_docs,
        estimated_alerts_per_hour=round(alerts_per_hour, 2),
        estimated_alerts_per_day=round(alerts_per_day, 2),
        cost_analysis=cost,
        recommendations=recommendations,
        mitre_techniques=rule.mitre_techniques,
    )
