"""KQL (Kibana Query Language) to Elasticsearch DSL translator.

Converts KQL query strings into native ES DSL queries that can be executed
directly against Elasticsearch without requiring the ES kql query type
(which may not be available in all versions).

Supported KQL syntax:
  field : value           → match_phrase
  field : "exact phrase"  → match_phrase
  field : (a OR b OR c)   → bool.should[match_phrase]
  field : *               → exists
  field : val*            → wildcard
  field >= value          → range (gte)
  field > value           → range (gt)
  field <= value          → range (lte)
  field < value           → range (lt)
  NOT field : value       → bool.must_not
  expr AND expr           → bool.must
  expr OR expr            → bool.should
  (grouped expressions)   → nested bool
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


def kql_to_dsl(kql: str) -> dict:
    """Convert a KQL query string to an Elasticsearch DSL query.

    Args:
        kql: The KQL query string (e.g. 'process.name : "cmd.exe" AND host.os : *').

    Returns:
        An ES DSL query dict ready for use in es.search(body={"query": ...}).
    """
    kql = kql.strip()
    if not kql or kql == "*":
        return {"match_all": {}}

    try:
        tokens = _tokenize(kql)
        result = _parse_or(tokens, 0)
        return result[0]
    except Exception as exc:
        logger.warning("KQL parse failed for '%s': %s — falling back to query_string", kql[:100], exc)
        return {
            "query_string": {
                "query": kql,
                "default_operator": "AND",
                "analyze_wildcard": True,
                "allow_leading_wildcard": True,
            }
        }


# ── Tokenizer ────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r"""
    (?P<quoted>"[^"]*")           |  # Quoted string
    (?P<lparen>\()                |  # Left paren
    (?P<rparen>\))                |  # Right paren
    (?P<gte>>=)                   |  # Greater than or equal
    (?P<lte><=)                   |  # Less than or equal
    (?P<gt>>)                     |  # Greater than
    (?P<lt><)                     |  # Less than
    (?P<colon>:)                  |  # KQL field separator
    (?P<and>\bAND\b)              |  # AND operator
    (?P<or>\bOR\b)                |  # OR operator
    (?P<not>\bNOT\b)              |  # NOT operator
    (?P<word>[^\s:()\"<>=]+)         # Unquoted word/value
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _tokenize(kql: str) -> list[tuple[str, str]]:
    """Tokenize a KQL string into (type, value) tuples."""
    tokens = []
    for m in _TOKEN_RE.finditer(kql):
        if m.group("quoted"):
            tokens.append(("VALUE", m.group("quoted").strip('"')))
        elif m.group("lparen"):
            tokens.append(("LPAREN", "("))
        elif m.group("rparen"):
            tokens.append(("RPAREN", ")"))
        elif m.group("gte"):
            tokens.append(("CMP", ">="))
        elif m.group("lte"):
            tokens.append(("CMP", "<="))
        elif m.group("gt"):
            tokens.append(("CMP", ">"))
        elif m.group("lt"):
            tokens.append(("CMP", "<"))
        elif m.group("colon"):
            tokens.append(("COLON", ":"))
        elif m.group("and"):
            tokens.append(("AND", "AND"))
        elif m.group("or"):
            tokens.append(("OR", "OR"))
        elif m.group("not"):
            tokens.append(("NOT", "NOT"))
        elif m.group("word"):
            tokens.append(("VALUE", m.group("word")))
    return tokens


# ── Recursive Descent Parser ─────────────────────────────────────────────────

def _parse_or(tokens: list, pos: int) -> tuple[dict, int]:
    """Parse OR expressions (lowest precedence)."""
    left, pos = _parse_and(tokens, pos)
    clauses = [left]

    while pos < len(tokens) and tokens[pos][0] == "OR":
        pos += 1  # skip OR
        right, pos = _parse_and(tokens, pos)
        clauses.append(right)

    if len(clauses) == 1:
        return clauses[0], pos
    return {"bool": {"should": clauses, "minimum_should_match": 1}}, pos


def _parse_and(tokens: list, pos: int) -> tuple[dict, int]:
    """Parse AND expressions."""
    left, pos = _parse_not(tokens, pos)
    clauses = [left]

    while pos < len(tokens) and tokens[pos][0] == "AND":
        pos += 1  # skip AND
        right, pos = _parse_not(tokens, pos)
        clauses.append(right)

    if len(clauses) == 1:
        return clauses[0], pos
    return {"bool": {"must": clauses}}, pos


def _parse_not(tokens: list, pos: int) -> tuple[dict, int]:
    """Parse NOT expressions."""
    if pos < len(tokens) and tokens[pos][0] == "NOT":
        pos += 1  # skip NOT
        expr, pos = _parse_atom(tokens, pos)
        return {"bool": {"must_not": [expr]}}, pos
    return _parse_atom(tokens, pos)


def _parse_atom(tokens: list, pos: int) -> tuple[dict, int]:
    """Parse atomic expressions: field:value, field>=value, parenthesized groups."""
    if pos >= len(tokens):
        return {"match_all": {}}, pos

    # Parenthesized group
    if tokens[pos][0] == "LPAREN":
        pos += 1  # skip (
        expr, pos = _parse_or(tokens, pos)
        if pos < len(tokens) and tokens[pos][0] == "RPAREN":
            pos += 1  # skip )
        return expr, pos

    # Check for field followed by operator (: or comparison)
    if pos + 1 < len(tokens) and tokens[pos][0] == "VALUE":
        next_type = tokens[pos + 1][0]

        # ── Comparison operators: field >= value, field > value, etc. ──
        if next_type == "CMP":
            field = tokens[pos][1]
            cmp_op = tokens[pos + 1][1]
            pos += 2  # skip field and operator

            if pos < len(tokens) and tokens[pos][0] == "VALUE":
                raw_value = tokens[pos][1]
                pos += 1

                # Convert to numeric if possible
                try:
                    value: int | float = int(raw_value)
                except ValueError:
                    try:
                        value = float(raw_value)
                    except ValueError:
                        value = raw_value

                op_map = {">=": "gte", ">": "gt", "<=": "lte", "<": "lt"}
                es_op = op_map.get(cmp_op, "gte")
                return {"range": {field: {es_op: value}}}, pos

        # ── Field : value expression ──
        if next_type == "COLON":
            field = tokens[pos][1]
            pos += 2  # skip field and colon

            # Value could be: single value, *, wildcard, or (a OR b OR c)
            if pos < len(tokens) and tokens[pos][0] == "LPAREN":
                # Value list: field : (val1 OR val2 OR val3)
                pos += 1  # skip (
                values = []
                while pos < len(tokens) and tokens[pos][0] != "RPAREN":
                    if tokens[pos][0] == "OR":
                        pos += 1
                        continue
                    values.append(tokens[pos][1])
                    pos += 1
                if pos < len(tokens) and tokens[pos][0] == "RPAREN":
                    pos += 1  # skip )

                if len(values) == 1:
                    return _make_field_query(field, values[0]), pos
                should = [_make_field_query(field, v) for v in values]
                return {"bool": {"should": should, "minimum_should_match": 1}}, pos
            elif pos < len(tokens) and tokens[pos][0] == "VALUE":
                value = tokens[pos][1]
                pos += 1
                return _make_field_query(field, value), pos

    # Bare value (shouldn't happen in well-formed KQL, but handle gracefully)
    if tokens[pos][0] == "VALUE":
        val = tokens[pos][1]
        pos += 1
        return {"multi_match": {"query": val, "lenient": True}}, pos

    # Skip unknown tokens
    pos += 1
    return {"match_all": {}}, pos


def _make_field_query(field: str, value: str) -> dict:
    """Create the appropriate ES query for a field:value pair."""
    # Exists check: field : *
    if value == "*":
        return {"exists": {"field": field}}

    # Wildcard: field : val*  or  field : *val
    if "*" in value or "?" in value:
        return {"wildcard": {field: {"value": value, "case_insensitive": True}}}

    # Exact match phrase
    return {"match_phrase": {field: value}}
