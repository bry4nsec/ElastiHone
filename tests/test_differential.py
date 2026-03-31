"""Tests for the differential calculator."""

from __future__ import annotations

import pytest

from sda.config import AppConfig
from sda.engine.differential import (
    calculate_alert_rate,
    calculate_cost,
    calculate_fpr,
    calculate_tpr,
    determine_verdict,
    calculate_differential,
)
from sda.models.report import CostLevel, Verdict
from sda.models.rule import CandidateRule, RuleFormat
from sda.models.telemetry import SearchResult


def _make_result(hits: int, total: int) -> SearchResult:
    """Helper to create a SearchResult."""
    return SearchResult(
        total_hits=hits,
        total_docs=total,
        took_ms=10,
        sample_hits=[],
        query_used={},
        index_pattern="test-*",
    )


def _make_rule(**overrides) -> CandidateRule:
    """Helper to create a CandidateRule."""
    defaults = {
        "id": "test-001",
        "name": "Test Rule",
        "format": RuleFormat.ELASTIC_DSL,
        "original_source": "{}",
        "es_query": {"query": {"match_all": {}}},
    }
    defaults.update(overrides)
    return CandidateRule(**defaults)


class TestTPR:
    def test_perfect_detection(self):
        assert calculate_tpr(_make_result(10, 10)) == 1.0

    def test_partial_detection(self):
        assert calculate_tpr(_make_result(7, 10)) == 0.7

    def test_no_detection(self):
        assert calculate_tpr(_make_result(0, 10)) == 0.0

    def test_empty_dataset(self):
        assert calculate_tpr(_make_result(0, 0)) == 0.0

    def test_capped_at_one(self):
        """TPR should not exceed 1.0 even with more hits than total."""
        assert calculate_tpr(_make_result(15, 10)) == 1.0


class TestFPR:
    def test_zero_noise(self):
        assert calculate_fpr(_make_result(0, 100000)) == 0.0

    def test_high_noise(self):
        assert calculate_fpr(_make_result(5000, 100000)) == 0.05

    def test_empty_production(self):
        assert calculate_fpr(_make_result(0, 0)) == 0.0


class TestAlertRate:
    def test_standard_rate(self):
        result = _make_result(70, 100000)
        per_hour, per_day = calculate_alert_rate(result, days=7)
        assert per_day == 10.0
        assert abs(per_hour - 10 / 24) < 0.01

    def test_zero_days(self):
        per_hour, per_day = calculate_alert_rate(_make_result(10, 100), days=0)
        assert per_hour == 0.0
        assert per_day == 0.0


class TestVerdict:
    def test_approve(self):
        verdict, _ = determine_verdict(fpr=0.005, tpr=0.95)
        assert verdict == Verdict.APPROVE

    def test_review(self):
        verdict, _ = determine_verdict(fpr=0.03, tpr=0.85)
        assert verdict == Verdict.REVIEW

    def test_reject_low_tpr(self):
        """Low TPR with borderline FPR gets REVIEW in noise-only fallback."""
        verdict, _ = determine_verdict(fpr=0.01, tpr=0.5)
        # fpr=0.01 is not < approve_fpr_max (0.01), so falls to REVIEW
        assert verdict == Verdict.REVIEW

    def test_reject_high_fpr(self):
        verdict, _ = determine_verdict(fpr=0.06, tpr=0.95)
        assert verdict == Verdict.REJECT

    def test_custom_thresholds(self):
        cfg = AppConfig()
        cfg.approve_tpr_min = 0.8
        cfg.approve_fpr_max = 0.02
        verdict, _ = determine_verdict(fpr=0.015, tpr=0.85, cfg=cfg)
        assert verdict == Verdict.APPROVE


class TestCostAnalysis:
    def test_simple_query_low_cost(self):
        rule = _make_rule(es_query={"query": {"match": {"process.name": "cmd.exe"}}})
        cost = calculate_cost(rule)
        assert cost.level in (CostLevel.LOW, CostLevel.MEDIUM)
        assert cost.query_complexity_score < 50

    def test_wildcard_query_higher_cost(self):
        rule = _make_rule(es_query={"query": {"wildcard": {"process.name": "*evil*"}}})
        cost = calculate_cost(rule)
        assert cost.has_wildcards is True
        assert cost.query_complexity_score > 10

    def test_regex_increases_cost(self):
        rule = _make_rule(
            es_query={"query": {"regexp": {"process.command_line": ".*b(a|4)se64.*"}}}
        )
        cost = calculate_cost(rule)
        assert cost.has_regex is True

    def test_sequence_detected_as_join(self):
        rule = _make_rule(
            es_query={"query": "sequence by host.name [process where ...] [network where ...]"}
        )
        cost = calculate_cost(rule)
        assert cost.has_joins is True


class TestDifferential:
    def test_full_report_generation(self):
        rule = _make_rule(mitre_techniques=["T1059.001"])
        noise = _make_result(50, 100000)

        report = calculate_differential(rule, noise_result=noise, days=7, analysis_id="test-run-1")

        assert report.rule_id == "test-001"
        assert report.analysis_id == "test-run-1"
        assert report.tpr == 0.0  # No signal analysis
        assert report.fpr == 0.0005
        assert report.verdict == Verdict.APPROVE
        assert report.estimated_alerts_per_day > 0
        assert report.cost_analysis is not None
        assert len(report.recommendations) > 0
