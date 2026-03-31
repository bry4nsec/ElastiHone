"""Tests for the rule execution engine (mock-based)."""

from __future__ import annotations

import pytest
from datetime import datetime, timezone

from sda.engine.executor import _inject_time_filter
from sda.models.rule import CandidateRule, RuleFormat


class TestTimeFilterInjection:
    """Tests for time-range filter injection into ES queries."""

    def test_inject_into_match_query(self):
        query = {"query": {"match": {"process.name": "cmd.exe"}}}
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        end = datetime(2025, 1, 7, tzinfo=timezone.utc)

        result = _inject_time_filter(query, start, end)

        assert "bool" in result["query"]
        assert "must" in result["query"]["bool"]
        must = result["query"]["bool"]["must"]
        assert len(must) == 2
        # First item is original query, second is time filter
        assert "match" in must[0]
        assert "range" in must[1]
        assert "@timestamp" in must[1]["range"]

    def test_inject_into_empty_query(self):
        query = {}
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        end = datetime(2025, 1, 7, tzinfo=timezone.utc)

        result = _inject_time_filter(query, start, end)

        assert "range" in result["query"]

    def test_does_not_mutate_original(self):
        query = {"query": {"match_all": {}}}
        original_str = str(query)
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        end = datetime(2025, 1, 7, tzinfo=timezone.utc)

        _inject_time_filter(query, start, end)

        assert str(query) == original_str


class TestRuleExceptionMerging:
    """Tests for exception clause merging into rule queries."""

    def test_add_single_exception(self):
        from sda.models.rule import ExceptionClause

        rule = CandidateRule(
            id="test",
            name="Test",
            format=RuleFormat.ELASTIC_DSL,
            original_source="{}",
            es_query={"query": {"match": {"process.name": "cmd.exe"}}},
        )

        exc = ExceptionClause(
            field="process.executable",
            operator="is_not",
            values=["C:\\Windows\\System32\\svchost.exe"],
            reason="Known Windows service",
        )

        refined = rule.with_exceptions([exc])

        # Should have one exception
        assert len(refined.exceptions) == 1
        # Query should now have must_not
        assert "must_not" in refined.es_query["query"]["bool"]

    def test_add_terms_exception(self):
        from sda.models.rule import ExceptionClause

        rule = CandidateRule(
            id="test",
            name="Test",
            format=RuleFormat.ELASTIC_DSL,
            original_source="{}",
            es_query={"query": {"match_all": {}}},
        )

        exc = ExceptionClause(
            field="source.ip",
            operator="not_in",
            values=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
            reason="Internal scanner IPs",
        )

        refined = rule.with_exceptions([exc])
        must_not = refined.es_query["query"]["bool"]["must_not"]
        assert any("terms" in clause for clause in must_not)

    def test_exceptions_accumulate(self):
        from sda.models.rule import ExceptionClause

        rule = CandidateRule(
            id="test",
            name="Test",
            format=RuleFormat.ELASTIC_DSL,
            original_source="{}",
            es_query={"query": {"match_all": {}}},
        )

        exc1 = ExceptionClause(field="process.name", operator="is_not", values=["svchost.exe"])
        exc2 = ExceptionClause(field="user.name", operator="is_not", values=["SYSTEM"])

        refined = rule.with_exceptions([exc1])
        refined2 = refined.with_exceptions([exc2])

        assert len(refined2.exceptions) == 2
