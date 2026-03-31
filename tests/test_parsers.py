"""Tests for rule parsers (Elastic only — Sigma was removed)."""

from __future__ import annotations

import json

import pytest

from sda.models.rule import CandidateRule, RuleFormat
from sda.parsers.elastic_parser import parse_elastic_rule

from conftest import SAMPLE_ELASTIC, SAMPLE_EQL


class TestElasticParser:
    """Tests for the Elastic Security JSON parser."""

    def test_parse_valid_elastic_rule(self):
        """Should parse a valid Elastic rule into a CandidateRule."""
        rule = parse_elastic_rule(SAMPLE_ELASTIC)

        assert isinstance(rule, CandidateRule)
        assert rule.name == "Test Elastic Rule"
        assert rule.id == "test-0002"
        assert rule.format == RuleFormat.ELASTIC_DSL

    def test_elastic_mitre_extraction(self):
        """Should extract technique and subtechnique IDs."""
        rule = parse_elastic_rule(SAMPLE_ELASTIC)

        assert "Execution" in rule.mitre_tactics
        assert "T1059" in rule.mitre_techniques
        assert "T1059.003" in rule.mitre_techniques

    def test_elastic_eql_detection(self):
        """Should detect EQL rules and set format accordingly."""
        rule = parse_elastic_rule(SAMPLE_EQL)

        assert rule.format == RuleFormat.ELASTIC_EQL
        assert rule.language == "eql"

    def test_elastic_generates_es_query(self):
        """Should produce a valid query body."""
        rule = parse_elastic_rule(SAMPLE_ELASTIC)

        assert "query" in rule.es_query
        # KQL translator produces native ES DSL (bool/match_phrase/wildcard)
        q = rule.es_query["query"]
        assert "bool" in q or "match_phrase" in q or "wildcard" in q or "match_all" in q

    def test_elastic_invalid_json(self):
        """Should raise ValueError for invalid JSON."""
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_elastic_rule("{not valid json}")

    def test_elastic_missing_name(self):
        """Should raise ValueError when name is missing."""
        with pytest.raises(ValueError, match="Missing required field"):
            parse_elastic_rule('{"type": "query"}')

    def test_elastic_index_patterns(self):
        """Should join multiple index patterns."""
        rule = parse_elastic_rule(SAMPLE_ELASTIC)
        assert "logs-*" in rule.target_indices
