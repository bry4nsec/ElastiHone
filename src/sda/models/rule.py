"""Rule domain models."""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field, computed_field


class RuleFormat(str, Enum):
    """Supported detection rule formats."""

    SIGMA = "sigma"
    ELASTIC_DSL = "elastic_dsl"
    ELASTIC_EQL = "elastic_eql"


class ExceptionClause(BaseModel):
    """A single exclusion / exception clause to reduce noise."""

    field: str = Field(description="ECS field path (e.g. process.executable)")
    operator: str = Field(default="is_not", description="Operator: is_not, not_in, wildcard_not")
    values: list[str] = Field(description="Values to exclude")
    reason: str = Field(default="", description="Human-readable justification")


class CandidateRule(BaseModel):
    """Internal normalised representation of a detection rule."""

    id: str = Field(description="Unique rule identifier")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(default="", description="Rule description")
    format: RuleFormat = Field(description="Source format")
    original_source: str = Field(default="", description="Raw YAML or JSON source text")
    rule_type: str = Field(default="query", description="Elastic rule type: query, eql, threshold, machine_learning, new_terms, esql, threat_match, saved_query")
    es_query: dict = Field(default_factory=dict, description="Normalised Elasticsearch DSL query body")
    language: str = Field(default="kuery", description="Query language: kuery, lucene, eql")
    target_indices: list[str] = Field(
        default_factory=lambda: ["logs-*"],
        description="Target index patterns (multi-index support)",
    )
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    severity: str = Field(default="medium")
    risk_score: int = Field(default=50, ge=0, le=100)
    exceptions: list[ExceptionClause] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the normalised query for deduplication."""
        import json

        raw = json.dumps(self.es_query, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def with_exceptions(self, new_exceptions: list[ExceptionClause]) -> CandidateRule:
        """Return a copy with additional exception clauses merged into the query."""
        merged = self.exceptions + new_exceptions

        # Build must_not clauses from exceptions
        must_not: list[dict] = []
        for exc in new_exceptions:
            if exc.operator == "is_not":
                for val in exc.values:
                    must_not.append({"match_phrase": {exc.field: val}})
            elif exc.operator == "not_in":
                must_not.append({"terms": {exc.field: exc.values}})
            elif exc.operator == "wildcard_not":
                for val in exc.values:
                    must_not.append({"wildcard": {exc.field: {"value": val}}})

        # Deep-merge must_not into query
        query = self.es_query.copy()
        if "query" in query:
            inner = query["query"]
            if "bool" not in inner:
                inner = {"bool": {"must": [inner]}}
                query["query"] = inner
            inner_bool = inner.setdefault("bool", {})
            existing_must_not = inner_bool.get("must_not", [])
            if isinstance(existing_must_not, dict):
                existing_must_not = [existing_must_not]
            inner_bool["must_not"] = existing_must_not + must_not

        return self.model_copy(update={"exceptions": merged, "es_query": query})
