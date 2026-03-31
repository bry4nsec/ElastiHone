"""Impact report and verdict models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Analysis verdict for a candidate rule."""

    APPROVE = "approve"
    REVIEW = "review"
    TUNE = "tune"
    REJECT = "reject"


class CostLevel(str, Enum):
    """Estimated CPU impact level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CostAnalysis(BaseModel):
    """Estimated computational cost of running the rule in production."""

    level: CostLevel = Field(description="Overall cost classification")
    query_complexity_score: int = Field(
        default=0, ge=0, le=100, description="0-100 complexity score"
    )
    has_wildcards: bool = Field(default=False)
    has_regex: bool = Field(default=False)
    has_nested_aggregations: bool = Field(default=False)
    has_joins: bool = Field(default=False, description="EQL sequence / join queries")
    estimated_cpu_pct_per_execution: float = Field(
        default=0.0, description="Rough CPU % per scheduled execution"
    )
    notes: str = Field(default="", description="Additional cost notes")


class OptimizationStep(BaseModel):
    """Record of a single optimisation iteration."""

    iteration: int = Field(ge=1)
    action: str = Field(description="What the agent did (e.g. 'Added exception for svchost.exe')")
    tpr_before: float
    tpr_after: float
    fpr_before: float
    fpr_after: float
    exceptions_added: list[dict] = Field(default_factory=list)


class ImpactReport(BaseModel):
    """Full detection impact report — the final output of the analysis pipeline."""

    # Identification
    rule_id: str
    rule_name: str
    rule_type: str = Field(default="", description="Rule type (query, threshold, eql, etc.)")
    severity: str = Field(default="medium", description="Rule severity (low, medium, high, critical)")
    target_indices: list[str] = Field(default_factory=list, description="Target index patterns")
    analysis_id: str = Field(description="Unique analysis run identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Verdict
    verdict: Verdict
    verdict_reason: str = Field(default="", description="Explanation of verdict")

    # Signal analysis (optional — only if signal index is used)
    tpr: float = Field(default=0.0, ge=0.0, le=1.0, description="True Positive Rate (0 if signal not used)")
    signal_hits: int = Field(default=0, ge=0, description="Number of attack events detected")
    signal_total: int = Field(default=0, ge=0, description="Total attack events injected")

    # Noise analysis (volumetry)
    fpr: float = Field(ge=0.0, le=1.0, description="False Positive Rate")
    noise_hits: int = Field(ge=0, description="Matches in production telemetry (raw query)")
    noise_total: int = Field(ge=0, description="Total production events scanned")
    actual_alert_count: int = Field(default=-1, description="Actual alerts from .alerts-security.alerts-* (-1 if unavailable)")
    sample_alerts: list[dict] = Field(default_factory=list, description="Sample alert documents for display")
    alert_distributions: dict = Field(default_factory=dict, description="Field distributions from all alerts")
    predicted_alert_count: int = Field(default=-1, description="Predicted deduplicated alerts via suppression aggregation")
    suppression_fields: list[str] = Field(default_factory=list, description="alert_suppression.group_by fields")
    suppression_method: str = Field(default="", description="How alert count was predicted")
    suppression_duration: str = Field(default="", description="Suppression time window (e.g. 5m, 1h)")
    estimated_alerts_per_hour: float = Field(ge=0.0)
    estimated_alerts_per_day: float = Field(ge=0.0)

    # Cost
    cost_analysis: CostAnalysis

    # Optimisation
    refined_rule: dict | None = Field(
        default=None, description="Optimised rule as JSON (with exceptions applied)"
    )
    optimization_history: list[OptimizationStep] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    is_behavioral: bool = Field(default=False, description="Whether this is a behavioral/Elastic Defend rule")

    # Metadata
    mitre_techniques: list[str] = Field(default_factory=list)
    analysis_duration_seconds: float = Field(default=0.0)
    ai_tokens_used: int = Field(default=0, description="Total LLM tokens consumed in Phase 2")
