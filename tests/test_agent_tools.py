"""Tests for the investigation tools (sda.agent.investigation_tools).

Tests focus on the new features: tool call budget, field mapping cache,
and RunContext deps injection. ES calls are mocked.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest

from sda.agent.investigation_tools import (
    InvestigationContext,
    investigate_aggregate,
    investigate_drill_down,
    investigate_get_fields,
    investigate_simulate_exclusion,
)
from sda.config import ElasticsearchConfig


@pytest.fixture
def inv_ctx():
    """Create a test InvestigationContext with mocked ES config."""
    cfg = ElasticsearchConfig(
        url="https://localhost:9200",
        username="test",
        password="test",
        production_indices="logs-*",
    )
    return InvestigationContext(
        index_pattern="logs-*",
        base_query={"query": {"match_all": {}}},
        time_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        time_end=datetime(2026, 1, 8, tzinfo=timezone.utc),
        cfg=cfg,
    )


class FakeRunContext:
    """Minimal RunContext substitute for testing tools."""

    def __init__(self, deps):
        self.deps = deps


class TestToolCallBudget:
    """Test that tools respect the MAX_TOOL_CALLS budget."""

    def test_budget_increments(self, inv_ctx):
        assert inv_ctx._tool_call_count == 0
        inv_ctx.check_budget()
        assert inv_ctx._tool_call_count == 1
        inv_ctx.check_budget()
        assert inv_ctx._tool_call_count == 2

    def test_budget_raises_when_exceeded(self, inv_ctx):
        inv_ctx._tool_call_count = inv_ctx.MAX_TOOL_CALLS
        with pytest.raises(RuntimeError, match="Tool call budget exceeded"):
            inv_ctx.check_budget()

    def test_default_budget_is_20(self):
        assert InvestigationContext.MAX_TOOL_CALLS == 20


class TestFieldMappingCache:
    """Test that get_fields caches results."""

    @patch("sda.agent.investigation_tools.get_field_mapping")
    def test_first_call_queries_es(self, mock_mapping, inv_ctx):
        mock_mapping.return_value = {
            "process.name": "keyword",
            "user.name": "keyword",
        }
        ctx = FakeRunContext(inv_ctx)

        result = investigate_get_fields(ctx)
        data = json.loads(result)

        assert data["total_fields"] == 2
        assert mock_mapping.call_count == 1

    @patch("sda.agent.investigation_tools.get_field_mapping")
    def test_second_call_uses_cache(self, mock_mapping, inv_ctx):
        mock_mapping.return_value = {"process.name": "keyword"}
        ctx = FakeRunContext(inv_ctx)

        result1 = investigate_get_fields(ctx)
        result2 = investigate_get_fields(ctx)

        assert result1 == result2
        assert mock_mapping.call_count == 1  # only called once

    def test_cache_starts_empty(self, inv_ctx):
        assert inv_ctx._field_cache is None


class TestAggregateValidation:
    """Test input validation for investigate_aggregate."""

    @patch("sda.agent.investigation_tools.aggregate_fields")
    def test_rejects_empty_fields(self, _mock, inv_ctx):
        ctx = FakeRunContext(inv_ctx)
        result = json.loads(investigate_aggregate(ctx, fields=[]))
        assert "error" in result

    @patch("sda.agent.investigation_tools.aggregate_fields")
    def test_rejects_too_many_fields(self, _mock, inv_ctx):
        ctx = FakeRunContext(inv_ctx)
        result = json.loads(investigate_aggregate(ctx, fields=["a", "b", "c", "d", "e"]))
        assert "error" in result

    @patch("sda.agent.investigation_tools.aggregate_fields")
    def test_valid_aggregation(self, mock_agg, inv_ctx):
        mock_agg.return_value = [{"key": "cmd.exe", "doc_count": 100}]
        ctx = FakeRunContext(inv_ctx)

        result = json.loads(investigate_aggregate(ctx, fields=["process.name"]))
        assert result["total_buckets"] == 1
        assert result["fields"] == ["process.name"]


class TestDrillDownValidation:
    """Test input validation for investigate_drill_down."""

    @patch("sda.agent.investigation_tools.drill_down")
    def test_rejects_empty_filters(self, _mock, inv_ctx):
        ctx = FakeRunContext(inv_ctx)
        result = json.loads(investigate_drill_down(ctx, filters={}))
        assert "error" in result

    @patch("sda.agent.investigation_tools.drill_down")
    def test_valid_drill_down(self, mock_dd, inv_ctx):
        mock_dd.return_value = [{"process.name": "cmd.exe", "user.name": "admin"}]
        ctx = FakeRunContext(inv_ctx)

        result = json.loads(investigate_drill_down(ctx, filters={"process.name": "cmd.exe"}))
        assert result["documents_returned"] == 1

    @patch("sda.agent.investigation_tools.drill_down")
    def test_size_capped_at_10(self, mock_dd, inv_ctx):
        mock_dd.return_value = []
        ctx = FakeRunContext(inv_ctx)

        investigate_drill_down(ctx, filters={"x": "y"}, size=50)
        _, kwargs = mock_dd.call_args
        assert kwargs["size"] == 10
