"""Elastic Security rule parser — supports all Elastic rule types."""

from __future__ import annotations

import json
import uuid

from sda.models.rule import CandidateRule, RuleFormat


# Rule types that have executable queries
QUERYABLE_TYPES = {"query", "eql", "threshold", "saved_query", "esql", "new_terms", "threat_match"}

# Rule types without a standard query (cannot execute against ES)
NON_QUERYABLE_TYPES = {"machine_learning"}


def _extract_mitre_from_threat(threat: list[dict]) -> tuple[list[str], list[str]]:
    """Extract MITRE tactics and techniques from Elastic rule 'threat' array."""
    tactics: list[str] = []
    techniques: list[str] = []
    for entry in threat:
        tactic = entry.get("tactic", {})
        if tactic_name := tactic.get("name"):
            tactics.append(tactic_name)
        for tech in entry.get("technique", []):
            if tech_id := tech.get("id"):
                techniques.append(tech_id)
            for sub in tech.get("subtechnique", []):
                if sub_id := sub.get("id"):
                    techniques.append(sub_id)
    return tactics, techniques


def _make_query_clause(query_str: str, language: str) -> dict:
    """Build the appropriate ES query clause based on the query language.

    KQL (kuery) → translates to native ES DSL via kql_translator
    Lucene      → uses 'query_string' query type
    """
    if language == "lucene":
        return {
            "query_string": {
                "query": query_str or "*",
                "default_operator": "AND",
                "analyze_wildcard": True,
            }
        }
    # Default: KQL — translate to native ES DSL
    from sda.parsers.kql_translator import kql_to_dsl
    return kql_to_dsl(query_str or "*")


def _build_es_query(rule_data: dict) -> tuple[dict, str]:
    """Build an Elasticsearch query body from an Elastic rule definition.

    Handles: query (KQL/Lucene), eql, threshold, saved_query, esql,
    new_terms, threat_match.

    Returns:
        Tuple of (query_body, language).
    """
    language = rule_data.get("language", "kuery")
    query_str = rule_data.get("query", "")
    rule_type = rule_data.get("type", "query")

    # ── EQL ────────────────────────────────────────────────────────────────
    if rule_type == "eql" or language == "eql":
        return {
            "query": query_str,
            "size": 100,
        }, "eql"

    # ── ES|QL ──────────────────────────────────────────────────────────────
    if rule_type == "esql":
        return {
            "query": query_str,
        }, "esql"

    # ── Machine Learning — no query ────────────────────────────────────────
    if rule_type == "machine_learning":
        return {}, "ml"

    # ── New Terms — has a query + new_terms_fields ─────────────────────────
    if rule_type == "new_terms":
        new_terms_fields = rule_data.get("new_terms", {}).get("field", [])
        q = _make_query_clause(query_str, language)
        return {
            "query": q,
            "_meta": {
                "new_terms_fields": new_terms_fields,
                "history_window_start": rule_data.get("new_terms", {}).get(
                    "history_window_start", "now-7d"
                ),
            },
        }, language or "kuery"

    # ── Threat Match (Indicator) — has a query + threat mapping ────────────
    if rule_type == "threat_match":
        threat_mapping = rule_data.get("threat_mapping", [])
        threat_index = rule_data.get("threat_index", [])
        q = _make_query_clause(query_str, language)
        return {
            "query": q,
            "_meta": {
                "threat_mapping": threat_mapping,
                "threat_index": threat_index,
            },
        }, language or "kuery"

    # ── Threshold ──────────────────────────────────────────────────────────
    if rule_type == "threshold":
        threshold = rule_data.get("threshold", {})
        threshold_field = threshold.get("field", [])
        if isinstance(threshold_field, list) and threshold_field:
            agg_field = threshold_field[0]
        elif isinstance(threshold_field, str):
            agg_field = threshold_field
        else:
            agg_field = "event.action"

        from sda.parsers.kql_translator import kql_to_dsl
        q = kql_to_dsl(query_str or "*")
        return {
            "query": q,
            "aggs": {
                "threshold_agg": {
                    "terms": {
                        "field": agg_field,
                        "min_doc_count": threshold.get("value", 1),
                    }
                }
            },
        }, language or "kuery"

    # ── KQL ────────────────────────────────────────────────────────────────
    if language == "kuery":
        from sda.parsers.kql_translator import kql_to_dsl
        return {
            "query": kql_to_dsl(query_str or "*")
        }, "kuery"

    # ── Lucene ─────────────────────────────────────────────────────────────
    if language == "lucene":
        return {
            "query": {
                "query_string": {
                    "query": query_str or "*",
                    "default_operator": "AND",
                }
            }
        }, "lucene"

    # ── Fallback ───────────────────────────────────────────────────────────
    return {"query": {"query_string": {"query": query_str or "*"}}}, language or "kuery"


def parse_elastic_rule(content: str) -> CandidateRule:
    """Parse an Elastic Security rule JSON string into a CandidateRule.

    Supports all Elastic rule types: query, eql, threshold,
    machine_learning, new_terms, esql, threat_match, saved_query.

    Args:
        content: Raw JSON string (single rule object).

    Returns:
        Normalised CandidateRule.

    Raises:
        ValueError: If the JSON is invalid or missing required fields.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Elastic rule must be a JSON object")

    name = data.get("name", "")
    if not name:
        raise ValueError("Missing required field: 'name'")

    rule_type = data.get("type", "query")

    threat = data.get("threat", [])
    tactics, techniques = _extract_mitre_from_threat(threat)

    es_query, language = _build_es_query(data)

    # Determine format
    if rule_type == "eql" or language == "eql":
        fmt = RuleFormat.ELASTIC_EQL
    else:
        fmt = RuleFormat.ELASTIC_DSL

    # Index patterns (ML rules may not have index)
    index = data.get("index", [])
    data_view_id = data.get("data_view_id", "")
    if not index and rule_type != "machine_learning":
        index = ["logs-*"]
    if isinstance(index, list):
        target_indices = index
    else:
        target_indices = [i.strip() for i in index.split(",")]

    severity = data.get("severity", "medium")
    risk_map = {"low": 25, "medium": 50, "high": 75, "critical": 100}
    tags = data.get("tags", [])

    # Store data_view_id in tags so orchestrator can resolve it
    if data_view_id:
        tags = list(tags)  # copy to avoid mutating original
        tags.append(f"__data_view_id:{data_view_id}")

    return CandidateRule(
        id=data.get("rule_id", data.get("id", str(uuid.uuid4()))),
        name=name,
        description=data.get("description", ""),
        format=fmt,
        rule_type=rule_type,
        original_source=content,
        es_query=es_query,
        language=language,
        target_indices=target_indices,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        severity=severity,
        risk_score=data.get("risk_score", risk_map.get(severity, 50)),
        tags=tags,
    )


def parse_toml_rule(toml_content: str) -> CandidateRule:
    """Parse an Elastic detection rule from TOML format (GitHub repo format).

    Converts the TOML structure into the JSON format consumed by
    parse_elastic_rule(), enabling the full analysis pipeline.

    Args:
        toml_content: Raw TOML text from the detection-rules repo.

    Returns:
        Normalised CandidateRule.

    Raises:
        ValueError: If the TOML is invalid or missing required fields.
    """
    from sda.github_rules import _parse_toml_rule

    try:
        rule_json = _parse_toml_rule(toml_content)
    except Exception as exc:
        raise ValueError(f"Invalid TOML rule: {exc}") from exc

    # Convert to JSON string and pass to existing parser
    return parse_elastic_rule(json.dumps(rule_json))
