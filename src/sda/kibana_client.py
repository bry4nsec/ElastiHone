"""Kibana Detection Engine API client — fetches rules from Elastic Security."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from sda.config import ElasticsearchConfig, get_config

logger = logging.getLogger(__name__)

# Kibana API requires this header for all requests
KIBANA_HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
}

# All supported Elastic rule types
ALL_RULE_TYPES = [
    "query",           # KQL / Lucene
    "eql",             # Event Query Language
    "threshold",       # Threshold aggregation
    "machine_learning",
    "new_terms",       # New Terms
    "esql",            # ES|QL
    "threat_match",    # Indicator Match
    "saved_query",     # Saved Query
]

# Rule type display labels and icons
RULE_TYPE_LABELS = {
    "query": ("KQL", ""),
    "eql": ("EQL", ""),
    "threshold": ("Threshold", ""),
    "machine_learning": ("ML", ""),
    "new_terms": ("New Terms", ""),
    "esql": ("ES|QL", ""),
    "threat_match": ("Indicator", ""),
    "saved_query": ("Saved Query", ""),
}


def _get_kibana_client(cfg: ElasticsearchConfig | None = None) -> tuple[httpx.Client, str, str]:
    """Create an httpx client configured for the Kibana API.

    Uses dedicated kibana_* credentials if set, otherwise falls back to ES credentials.

    Returns:
        Tuple of (httpx.Client, kibana_base_url, api_prefix).
        api_prefix is e.g. '/s/my-space' for non-default spaces, or '' for default.

    Raises:
        ValueError: If kibana_url is not configured.
    """
    if cfg is None:
        cfg = get_config().es

    kibana_url = cfg.kibana_url.rstrip("/")
    if not kibana_url:
        raise ValueError("Kibana URL not configured. Set it in Settings → Kibana Connection.")

    auth = None
    headers = dict(KIBANA_HEADERS)

    # Prefer Kibana-specific credentials, fall back to ES credentials
    kb_api_key = cfg.kibana_api_key or cfg.api_key
    kb_username = cfg.kibana_username or cfg.username
    kb_password = cfg.kibana_password or cfg.password

    if kb_api_key:
        headers["Authorization"] = f"ApiKey {kb_api_key}"
    elif kb_username and kb_password:
        auth = (kb_username, kb_password)

    # Kibana Space support: /s/{space_id} prefix
    space = (cfg.kibana_space or "").strip()
    api_prefix = f"/s/{space}" if space else ""

    client = httpx.Client(
        base_url=kibana_url,
        headers=headers,
        auth=auth,
        verify=cfg.verify_certs,
        timeout=30.0,
    )
    return client, kibana_url, api_prefix


def resolve_data_view(
    data_view_id: str,
    cfg: ElasticsearchConfig | None = None,
) -> str | None:
    """Resolve a Kibana data view ID to its index pattern.

    Uses the Kibana Data Views API: GET /api/data_views/data_view/{id}

    Returns:
        The index pattern string (e.g. 'siem-zscaler-weblogs*'), or None if
        the data view cannot be resolved.
    """
    try:
        client, kibana_url, api_prefix = _get_kibana_client(cfg)
    except ValueError:
        return None

    url = f"{kibana_url}{api_prefix}/api/data_views/data_view/{data_view_id}"
    try:
        resp = client.get(url, headers=KIBANA_HEADERS)
        resp.raise_for_status()
        dv = resp.json()
        title = dv.get("data_view", {}).get("title", "")
        if title:
            logger.info("Resolved data_view_id=%s to index pattern '%s'", data_view_id, title)
            return title
        return None
    except Exception as exc:
        logger.warning("Failed to resolve data_view_id=%s: %s", data_view_id, exc)
        return None
    finally:
        client.close()


def list_rules(
    cfg: ElasticsearchConfig | None = None,
    page: int = 1,
    per_page: int = 100,
    search: str = "",
    sort_field: str = "name",
    sort_order: str = "asc",
    rule_type: str = "",
    severity: str = "",
    source: str = "",
    status: str = "",
) -> dict[str, Any]:
    """List detection rules from Elastic Security.

    Supports all rule types: query (KQL), eql, threshold, machine_learning,
    new_terms, esql, threat_match, saved_query.

    Args:
        cfg: Optional ES config override.
        page: Page number (1-indexed).
        per_page: Rules per page (max 100).
        search: Optional search filter (rule name).
        sort_field: Field to sort by.
        sort_order: Sort direction (asc/desc).
        rule_type: Optional filter by rule type (e.g. 'eql', 'query').
        severity: Optional filter by severity (critical/high/medium/low).
        source: Optional filter by source ('elastic' for prebuilt, 'custom' for user-created).
        status: Optional filter by status ('enabled' or 'disabled').

    Returns:
        Dict with 'rules' (list of rule summaries) and 'total' count.
    """
    client, _, api_prefix = _get_kibana_client(cfg)

    params: dict[str, Any] = {
        "page": page,
        "per_page": min(per_page, 100),
        "sort_field": sort_field,
        "sort_order": sort_order,
    }

    # Build filter string — combine all filters with KQL
    # Kibana detection_engine/_find uses KQL against saved object attributes
    filters = []
    if search:
        filters.append(f"alert.attributes.name: *{search}*")
    if rule_type and rule_type in ALL_RULE_TYPES:
        filters.append(f"alert.attributes.params.type: {rule_type}")
    if severity and severity in ("critical", "high", "medium", "low"):
        filters.append(f"alert.attributes.params.severity: {severity}")
    if source == "elastic":
        filters.append("alert.attributes.params.immutable: true")
    elif source == "custom":
        filters.append("alert.attributes.params.immutable: false")
    if status == "enabled":
        filters.append("alert.attributes.enabled: true")
    elif status == "disabled":
        filters.append("alert.attributes.enabled: false")

    if filters:
        params["filter"] = " AND ".join(filters)

    try:
        resp = client.get(f"{api_prefix}/api/detection_engine/rules/_find", params=params)
        resp.raise_for_status()
        data = resp.json()

        rules = []
        for rule in data.get("data", []):
            rtype = rule.get("type", "query")
            label, icon = RULE_TYPE_LABELS.get(rtype, (rtype.upper(), ""))

            rules.append({
                "id": rule.get("id", ""),
                "rule_id": rule.get("rule_id", ""),
                "name": rule.get("name", "Unknown"),
                "severity": rule.get("severity", "medium"),
                "enabled": rule.get("enabled", False),
                "type": rtype,
                "type_label": label,
                "type_icon": icon,
                "immutable": rule.get("immutable", False),  # True = Elastic prebuilt
                "index": rule.get("index", []),
                "tags": rule.get("tags", []),
                "risk_score": rule.get("risk_score", 0),
                "updated_at": rule.get("updated_at", ""),
                "language": rule.get("language", ""),
            })

        return {
            "rules": rules,
            "total": data.get("total", 0),
            "page": data.get("page", page),
            "per_page": data.get("perPage", per_page),
        }
    except httpx.HTTPStatusError as exc:
        logger.error("Kibana API error: %s %s", exc.response.status_code, exc.response.text[:200])
        raise ValueError(f"Kibana API error ({exc.response.status_code}): {exc.response.text[:200]}") from exc
    except httpx.ConnectError as exc:
        raise ValueError(f"Cannot connect to Kibana: {exc}") from exc
    finally:
        client.close()


def get_rule_coverage_stats(cfg: ElasticsearchConfig | None = None) -> dict[str, Any]:
    """Compute comprehensive rule coverage statistics from Kibana.

    Fetches all rules in batches and returns:
    - enabled/disabled counts per severity
    - total coverage percentage
    - deprecated rule count and names
    - rules with no integrations count and names
    """
    client, _, api_prefix = _get_kibana_client(cfg)

    all_rules = []
    page = 1
    per_page = 100

    try:
        while True:
            resp = client.get(
                f"{api_prefix}/api/detection_engine/rules/_find",
                params={"page": page, "per_page": per_page, "sort_field": "name", "sort_order": "asc"},
            )
            resp.raise_for_status()
            data = resp.json()
            rules = data.get("data", [])
            all_rules.extend(rules)
            total = data.get("total", 0)
            if len(all_rules) >= total or not rules:
                break
            page += 1
    except Exception as exc:
        logger.warning("Failed to fetch rules for coverage stats: %s", exc)
    finally:
        client.close()

    # Aggregate stats
    by_severity = {
        "critical": {"enabled": 0, "disabled": 0},
        "high": {"enabled": 0, "disabled": 0},
        "medium": {"enabled": 0, "disabled": 0},
        "low": {"enabled": 0, "disabled": 0},
    }
    totals = {"enabled": 0, "disabled": 0, "total": len(all_rules)}
    deprecated_rules = []
    no_integration_rules = []

    for rule in all_rules:
        sev = (rule.get("severity") or "medium").lower()
        enabled = rule.get("enabled", False)
        status_key = "enabled" if enabled else "disabled"
        name = rule.get("name", "Unknown")

        if sev in by_severity:
            by_severity[sev][status_key] += 1
        totals[status_key] += 1

        # Check deprecated — Elastic marks via tags
        tags = rule.get("tags", [])
        is_deprecated = any(
            "deprecat" in (t or "").lower()
            for t in tags
        )
        if is_deprecated:
            deprecated_rules.append({
                "name": name,
                "severity": sev,
                "enabled": enabled,
                "id": rule.get("id", ""),
            })

        # Check related integrations
        integrations = rule.get("related_integrations", [])
        if not integrations and rule.get("immutable", False):
            # Only flag Elastic prebuilt rules (immutable) missing integrations
            no_integration_rules.append({
                "name": name,
                "severity": sev,
                "enabled": enabled,
                "id": rule.get("id", ""),
            })

    coverage_pct = round(totals["enabled"] / max(totals["total"], 1) * 100, 1)

    return {
        "by_severity": by_severity,
        "totals": totals,
        "coverage_pct": coverage_pct,
        "deprecated": {
            "count": len(deprecated_rules),
            "rules": deprecated_rules[:50],  # Cap to avoid huge responses
        },
        "no_integrations": {
            "count": len(no_integration_rules),
            "rules": no_integration_rules[:50],
        },
    }



def fetch_rule(rule_id: str, cfg: ElasticsearchConfig | None = None) -> dict[str, Any]:
    """Fetch a single detection rule by its ID.

    Args:
        rule_id: The Kibana saved object ID of the rule.
        cfg: Optional ES config override.

    Returns:
        Full rule definition as JSON dict.
    """
    client, _, api_prefix = _get_kibana_client(cfg)

    try:
        resp = client.get(f"{api_prefix}/api/detection_engine/rules", params={"id": rule_id})
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("Kibana API error fetching rule %s: %s", rule_id, exc.response.status_code)
        raise ValueError(f"Failed to fetch rule '{rule_id}': {exc.response.status_code}") from exc
    finally:
        client.close()


def _entries_to_must_not(entries: list[dict]) -> list[dict]:
    """Convert Elastic exception list entries to Elasticsearch must_not clauses.

    Supports entry types: match, match_any, exists, wildcard, list.
    Handles operators: included (exception = must_not) and excluded.
    """
    must_not: list[dict] = []

    for entry in entries:
        field = entry.get("field", "")
        entry_type = entry.get("type", "")
        operator = entry.get("operator", "included")
        value = entry.get("value", "")

        if not field:
            continue

        # Only 'included' entries create must_not clauses
        # 'excluded' means "only match when this field IS present" (rare)
        if operator != "included":
            continue

        if entry_type == "match":
            must_not.append({"match_phrase": {field: value}})

        elif entry_type == "match_any":
            values = entry.get("value", [])
            if isinstance(values, list) and values:
                must_not.append({"terms": {field: values}})

        elif entry_type == "exists":
            must_not.append({"exists": {"field": field}})

        elif entry_type == "wildcard":
            must_not.append({"wildcard": {field: {"value": value}}})

        elif entry_type == "list":
            # List-based exceptions reference another list — can't inline,
            # but we log it for awareness
            list_id = entry.get("list", {}).get("id", "unknown")
            logger.info("Skipping list-type exception referencing list '%s' (not inlineable)", list_id)

    return must_not


def fetch_rule_exceptions(
    rule_data: dict,
    cfg: ElasticsearchConfig | None = None,
) -> list[dict]:
    """Fetch all exception list items for a rule and convert to must_not clauses.

    Args:
        rule_data: Full rule JSON from fetch_rule() — must contain 'exceptions_list'.
        cfg: Optional ES config override.

    Returns:
        List of Elasticsearch must_not clause dicts. Empty if no exceptions.
    """
    exceptions_list = rule_data.get("exceptions_list", [])
    if not exceptions_list:
        logger.info("Rule has no exception lists")
        return []

    client, _, api_prefix = _get_kibana_client(cfg)
    all_must_not: list[dict] = []

    try:
        for exc_ref in exceptions_list:
            list_id = exc_ref.get("list_id", "")
            namespace_type = exc_ref.get("namespace_type", "single")

            if not list_id:
                continue

            logger.info("Fetching exception list items: list_id='%s' (namespace=%s)",
                        list_id, namespace_type)

            # Fetch all items for this exception list
            params: dict[str, Any] = {
                "list_id": list_id,
                "namespace_type": namespace_type,
                "page": 1,
                "per_page": 100,
            }

            resp = client.get(
                f"{api_prefix}/api/exception_lists/items/_find",
                params=params,
            )
            resp.raise_for_status()
            data = resp.json()

            items = data.get("data", [])
            total = data.get("total", 0)
            logger.info("Found %d exception items in list '%s'", total, list_id)

            for item in items:
                item_entries = item.get("entries", [])
                clauses = _entries_to_must_not(item_entries)
                all_must_not.extend(clauses)
                if clauses:
                    logger.info("Exception '%s': %d must_not clauses generated",
                                item.get("name", "unnamed"), len(clauses))

    except httpx.HTTPStatusError as exc:
        logger.warning("Failed to fetch exception lists: %s %s",
                       exc.response.status_code, exc.response.text[:200])
    except httpx.ConnectError as exc:
        logger.warning("Cannot connect to Kibana for exceptions: %s", exc)
    finally:
        client.close()

    logger.info("Total must_not clauses from exceptions: %d", len(all_must_not))
    return all_must_not


def search_alerts(
    rule_name: str,
    days: int = 7,
    rule_uuid: str = "",
    cfg: ElasticsearchConfig | None = None,
) -> dict[str, Any]:
    """Search Kibana Security Alerts for a specific rule name.

    Uses the Detection Engine signals search API which returns the exact same
    deduplicated alerts visible in the Kibana Security Alerts UI.
    Tries name-based match first, then UUID-based fallback.

    Args:
        rule_name: The rule name to search for.
        days: Number of days to look back.
        rule_uuid: Optional Kibana rule UUID for fallback matching.
        cfg: Optional ES config override.

    Returns:
        Dict with 'alert_count', 'sample_alerts', 'distributions', 'took_ms'.
    """
    client, _, api_prefix = _get_kibana_client(cfg)

    # Build multiple query strategies
    prefixed_name = f"Malicious Behavior Detection Alert: {rule_name}"

    strategies = [
        {
            "label": f"name='{rule_name}'",
            "query": {
                "bool": {
                    "must": [
                        {"bool": {
                            "should": [
                                {"match_phrase": {"kibana.alert.rule.name": rule_name}},
                                {"match_phrase": {"kibana.alert.rule.name": prefixed_name}},
                            ],
                            "minimum_should_match": 1,
                        }},
                        {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}},
                    ]
                }
            },
        },
    ]
    if rule_uuid:
        strategies.append({
            "label": f"uuid='{rule_uuid}'",
            "query": {
                "bool": {
                    "must": [
                        {"bool": {
                            "should": [
                                {"term": {"kibana.alert.rule.uuid": rule_uuid}},
                                {"term": {"signal.rule.id": rule_uuid}},
                            ],
                            "minimum_should_match": 1,
                        }},
                        {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}},
                    ]
                }
            },
        })

    # Aggregation fields for distributions
    agg_fields = [
        "host.name", "user.name",
        "process.executable", "process.name",
        "process.parent.executable", "process.parent.name",
        "process.code_signature.subject_name",
        "event.action", "event.category",
        "source.ip", "destination.ip",
        "file.path", "file.name",
        "url.domain",
    ]
    field_aggs = {}
    for f in agg_fields:
        safe_name = f.replace(".", "_")
        field_aggs[f"top_{safe_name}"] = {
            "terms": {"field": f, "size": 25}
        }

    url = f"{api_prefix}/api/detection_engine/signals/search"

    for strategy in strategies:
        body = {
            "query": strategy["query"],
            "fields": ["*"],
            "_source": False,
            "size": 10,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "track_total_hits": True,
            "aggs": {
                "unique_alerts": {"cardinality": {"field": "kibana.alert.uuid"}},
                **field_aggs,
            },
        }

        try:
            logger.info("search_alerts: trying strategy %s via %s", strategy["label"], url)
            resp = client.post(url, json=body)

            if resp.status_code >= 400:
                logger.warning("search_alerts strategy %s failed: %s %s",
                               strategy["label"], resp.status_code, resp.text[:300])
                continue

            data = resp.json()

            raw_total = data.get("hits", {}).get("total", {})
            if isinstance(raw_total, dict):
                raw_total = raw_total.get("value", 0)

            logger.info("search_alerts strategy %s: %d hits", strategy["label"], raw_total)

            if raw_total == 0:
                continue

            aggs = data.get("aggregations", {})
            unique = aggs.get("unique_alerts", {}).get("value", 0)
            total = unique if unique > 0 else raw_total

            hits = data.get("hits", {}).get("hits", [])

            # Extract ECS fields from the 'fields' response
            samples = []
            for h in hits[:10]:
                fields_data = h.get("fields", {})
                flat = {}
                for k, v in fields_data.items():
                    flat[k] = v[0] if isinstance(v, list) and len(v) == 1 else v
                if not flat:
                    flat = h.get("_source", {})
                samples.append(flat)

            # Build field distributions from aggregations
            distributions: dict[str, list[dict]] = {}
            for f in agg_fields:
                safe_name = f.replace(".", "_")
                agg_data = aggs.get(f"top_{safe_name}", {})
                buckets = agg_data.get("buckets", [])
                if buckets:
                    distributions[f] = [
                        {"value": b["key"], "count": b["doc_count"],
                         "pct": round(b["doc_count"] / max(raw_total, 1) * 100, 1)}
                        for b in buckets
                    ]
            took = data.get("took", 0)

            logger.info(
                "Kibana alerts for '%s': %d alerts (%d unique) in last %d days "
                "(took %dms, strategy: %s)",
                rule_name, raw_total, unique, days, took, strategy["label"],
            )

            return {
                "alert_count": total,
                "sample_alerts": samples,
                "distributions": distributions,
                "took_ms": took,
            }

        except httpx.HTTPStatusError as exc:
            logger.warning("search_alerts %s error: %s %s",
                           strategy["label"], exc.response.status_code, exc.response.text[:200])
            continue

    logger.warning("All search_alerts strategies failed for '%s'", rule_name)
    client.close()
    return {"alert_count": 0, "sample_alerts": [], "distributions": {}, "took_ms": 0}


def get_alert_subtypes(
    rule_name: str,
    days: int = 7,
    rule_uuid: str = "",
    cfg: ElasticsearchConfig | None = None,
) -> dict[str, Any]:
    """Get alert subtypes for an envelope rule.

    Tries multiple query strategies and candidate fields for aggregation.
    Strategy 1: Match by kibana.alert.rule.name
    Strategy 2: Match by kibana.alert.rule.uuid (fallback)
    For each strategy, tries multiple aggregation fields.

    Returns:
        Dict with 'rule_name', 'total', 'subtypes' list of {message, count}.
    """
    client, _, api_prefix = _get_kibana_client(cfg)

    # Build queries — try name first, then UUID
    queries = []
    # Strategy 1: By rule name
    queries.append({
        "label": f"name='{rule_name}'",
        "query": {
            "bool": {
                "must": [
                    {"match_phrase": {"kibana.alert.rule.name": rule_name}},
                    {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}},
                ]
            }
        }
    })
    # Strategy 2: By rule UUID (if provided)
    if rule_uuid:
        queries.append({
            "label": f"uuid='{rule_uuid}'",
            "query": {
                "bool": {
                    "must": [
                        {"bool": {
                            "should": [
                                {"term": {"kibana.alert.rule.uuid": rule_uuid}},
                                {"term": {"signal.rule.id": rule_uuid}},
                            ],
                            "minimum_should_match": 1,
                        }},
                        {"range": {"@timestamp": {"gte": f"now-{days}d", "lte": "now"}}},
                    ]
                }
            }
        })

    # Candidate aggregation fields — ordered by priority (most descriptive first)
    # kibana.alert.rule.name contains the specific sub-rule name for envelope rules
    # (e.g. "Memory Threat Detection Alert: Shellcode Injection")
    candidate_fields = [
        "kibana.alert.rule.name",        # Specific sub-rule name (best for subtypes)
        "kibana.alert.reason.keyword",   # Full alert reason text
        "message.keyword",               # Alert message with detection name
        "rule.name",                      # Agent-level rule name
        "kibana.alert.reason",            # Reason (text, may not aggregate)
        "event.action",                   # Least useful — generic like "start"
    ]

    # Generic values to filter out (not useful as subtypes)
    _GENERIC_VALUES = {"start", "end", "open", "close", "creation", "allowed", "denied"}

    field_aggs = {}
    for f in candidate_fields:
        safe = f.replace(".", "_")
        field_aggs[f"by_{safe}"] = {
            "terms": {"field": f, "size": 200, "order": {"_count": "desc"}},
        }

    url = f"{api_prefix}/api/detection_engine/signals/search"

    for strategy in queries:
        body = {
            "query": strategy["query"],
            "size": 10,
            "fields": ["message", "rule.name", "event.action", "kibana.alert.reason",
                       "kibana.alert.rule.name", "kibana.alert.rule.uuid"],
            "_source": False,
            "track_total_hits": True,
            "aggs": field_aggs,
        }

        try:
            logger.info("Alert subtypes: trying strategy %s via %s", strategy["label"], url)
            resp = client.post(url, json=body)

            if resp.status_code >= 400:
                logger.warning("Alert subtypes strategy %s failed: %s %s",
                               strategy["label"], resp.status_code, resp.text[:300])
                continue

            data = resp.json()

            raw_total = data.get("hits", {}).get("total", {})
            if isinstance(raw_total, dict):
                raw_total = raw_total.get("value", 0)

            logger.info("Alert subtypes strategy %s: %d total hits", strategy["label"], raw_total)

            if raw_total == 0:
                continue

            aggs = data.get("aggregations", {})

            # Pick the FIRST field in priority order that has useful buckets
            # (most descriptive field wins, not most buckets)
            best_field = None
            best_buckets = []
            for f in candidate_fields:
                safe = f.replace(".", "_")
                buckets = aggs.get(f"by_{safe}", {}).get("buckets", [])
                # Filter out generic/useless values
                useful = [b for b in buckets
                          if str(b.get("key", "")).lower() not in _GENERIC_VALUES]
                logger.info("  agg '%s': %d buckets (%d useful)", f, len(buckets), len(useful))
                if useful and not best_buckets:
                    # Take the FIRST field with useful results (priority order)
                    best_field = f
                    best_buckets = useful

            subtypes = []
            if best_buckets:
                subtypes = [
                    {"message": b["key"], "count": b["doc_count"]}
                    for b in best_buckets
                ]
            else:
                # Fallback: extract from sample hits
                hits = data.get("hits", {}).get("hits", [])
                msg_counts: dict[str, int] = {}
                for h in hits:
                    fields_data = h.get("fields", {})
                    msg = None
                    for fld in ["message", "rule.name", "event.action", "kibana.alert.reason"]:
                        val = fields_data.get(fld)
                        if val:
                            msg = val[0] if isinstance(val, list) else val
                            break
                    if msg:
                        msg_counts[msg] = msg_counts.get(msg, 0) + 1
                if msg_counts:
                    subtypes = sorted(
                        [{"message": k, "count": v} for k, v in msg_counts.items()],
                        key=lambda x: x["count"], reverse=True,
                    )
                    best_field = "sample"

            logger.info(
                "Alert subtypes for '%s': %d total, %d subtypes (field: %s, strategy: %s)",
                rule_name, raw_total, len(subtypes), best_field or "none", strategy["label"],
            )

            return {
                "rule_name": rule_name,
                "total": raw_total,
                "subtypes": subtypes,
            }

        except httpx.HTTPStatusError as exc:
            logger.warning("Alert subtypes %s error: %s %s",
                           strategy["label"], exc.response.status_code, exc.response.text[:200])
            continue

    logger.warning("All alert subtypes strategies failed for '%s'", rule_name)
    client.close()
    return {"rule_name": rule_name, "total": 0, "subtypes": []}


def apply_exception(
    rule_id: str,
    rule_name: str,
    entries: list[dict],
    list_name: str = "",
    exception_item_name: str = "",
    cfg: ElasticsearchConfig | None = None,
) -> dict:
    """Push an exception to Kibana's Exception List API.

    Creates an exception list (if it doesn't exist) and adds exception items
    with the provided entries.

    Args:
        rule_id: The rule ID to attach the exception to
        rule_name: Rule name (used for list naming)
        entries: Exception entries (field/operator/type/value dicts)
        list_name: Custom exception list name (auto-generated if empty)
        exception_item_name: Name for the exception item (auto-generated if empty)
        cfg: ES config (loaded from env if None)

    Returns:
        Dict with list_id, item_id, and status
    """
    if cfg is None:
        from sda.config import get_config
        cfg = get_config().es

    try:
        client, _base_url, api_prefix = _get_kibana_client(cfg)
    except (ValueError, Exception) as exc:
        return {"error": f"Kibana not configured: {exc}", "status": "failed"}

    if not list_name:
        safe_name = rule_name.replace(" ", "_").lower()[:50]
        list_name = f"sda_exceptions_{safe_name}"

    list_id = list_name.replace(" ", "_").lower()

    if not exception_item_name:
        exception_item_name = f"ElastiHone exclusion for {rule_name}"

    try:
        # Step 1: Create exception list (idempotent — returns existing if already created)
        list_body = {
            "list_id": list_id,
            "name": f"ElastiHone: {rule_name}",
            "description": f"Auto-generated exceptions by ElastiHone for rule: {rule_name}",
            "type": "detection",
            "namespace_type": "single",
        }
        resp = client.post(
            f"{api_prefix}/api/exception_lists",
            json=list_body,
        )
        if resp.status_code == 409:
            # List already exists — that's fine
            logger.info("Exception list '%s' already exists", list_id)
        elif resp.status_code >= 400:
            logger.warning("Failed to create exception list: %s %s",
                          resp.status_code, resp.text[:200])
            return {"error": f"Failed to create list: {resp.status_code}", "status": "failed"}
        else:
            logger.info("Created exception list: %s", list_id)

        # Step 2: Add exception item — fix entry formats for Kibana API
        # Kibana requires match_any values as a list, not a comma string
        clean_entries = []
        for e in entries:
            entry = dict(e)  # shallow copy
            if entry.get("type") == "match_any" and isinstance(entry.get("value"), str):
                entry["value"] = [v.strip() for v in entry["value"].split(",")]
            clean_entries.append(entry)

        item_body = {
            "list_id": list_id,
            "name": exception_item_name,
            "description": "Auto-generated by ElastiHone AI investigation",
            "type": "simple",
            "namespace_type": "single",
            "entries": clean_entries,
        }
        item_resp = client.post(
            f"{api_prefix}/api/exception_lists/items",
            json=item_body,
        )
        if item_resp.status_code >= 400:
            body = item_resp.text[:500]
            logger.warning("Failed to create exception item: %s %s", item_resp.status_code, body)
            return {"error": f"Kibana rejected exception entries ({item_resp.status_code}): {body}", "status": "failed"}
        item_data = item_resp.json()

        logger.info("Exception item created: %s (list: %s)", item_data.get("id"), list_id)

        # Step 3: Link exception list to the rule
        # Multi-tier rule lookup:
        # 1. rule_id param (string identifier)
        # 2. id param (saved object UUID)
        # 3. Exact name search via _find API
        # 4. Behavioral envelope rule fallback ("Behavior - Detected - Elastic Defend")
        rule_linked = False
        if rule_id or rule_name:
            rule_data = None
            try:
                # Tier 1: rule_id param (string identifier like "evasion_via_sleep_api_hooking")
                if rule_id:
                    logger.info("Linking: Tier 1 — trying rule_id='%s'", rule_id)
                    rule_resp = client.get(
                        f"{api_prefix}/api/detection_engine/rules",
                        params={"rule_id": rule_id},
                    )
                    if rule_resp.status_code == 200:
                        rule_data = rule_resp.json()
                        logger.info("Linking: Tier 1 succeeded — found '%s'", rule_data.get("name"))

                # Tier 2: saved object UUID
                if not rule_data and rule_id:
                    logger.info("Linking: Tier 2 — trying id='%s'", rule_id)
                    rule_resp = client.get(
                        f"{api_prefix}/api/detection_engine/rules",
                        params={"id": rule_id},
                    )
                    if rule_resp.status_code == 200:
                        rule_data = rule_resp.json()
                        logger.info("Linking: Tier 2 succeeded — found '%s'", rule_data.get("name"))

                # Tier 3: Exact name search via _find API
                if not rule_data and rule_name:
                    logger.info("Linking: Tier 3 — searching by name '%s'", rule_name)
                    safe_name = rule_name.replace('"', r'\"')
                    find_resp = client.get(
                        f"{api_prefix}/api/detection_engine/rules/_find",
                        params={
                            "filter": f'alert.attributes.name: "{safe_name}"',
                            "per_page": 5,
                        },
                    )
                    if find_resp.status_code == 200:
                        find_data = find_resp.json()
                        results = find_data.get("data", [])
                        logger.info("Linking: Tier 3 — name search returned %d results", len(results))
                        for r in results:
                            if r.get("name", "").lower() == rule_name.lower():
                                rule_data = r
                                logger.info("Linking: Tier 3 succeeded — exact match '%s' (rule_id=%s)",
                                             r.get("name"), r.get("rule_id"))
                                break
                        if not rule_data and results:
                            rule_data = results[0]
                            logger.info("Linking: Tier 3 — using closest match '%s'", rule_data.get("name"))
                    else:
                        logger.warning("Linking: Tier 3 failed — %s %s",
                                       find_resp.status_code, find_resp.text[:200])

                # Tier 4: Behavioral envelope rule fallback
                # Behavioral rules from protections-artifacts don't have matching
                # Kibana detection rules. Link to "Behavior - Detected - Elastic Defend"
                if not rule_data:
                    behavioral_envelope = "Behavior - Detected - Elastic Defend"
                    logger.info("Linking: Tier 4 — searching for behavioral envelope rule '%s'",
                                behavioral_envelope)
                    find_resp = client.get(
                        f"{api_prefix}/api/detection_engine/rules/_find",
                        params={
                            "filter": f'alert.attributes.name: "{behavioral_envelope}"',
                            "per_page": 5,
                        },
                    )
                    if find_resp.status_code == 200:
                        find_data = find_resp.json()
                        results = find_data.get("data", [])
                        logger.info("Linking: Tier 4 — envelope search returned %d results", len(results))
                        for r in results:
                            if behavioral_envelope.lower() in r.get("name", "").lower():
                                rule_data = r
                                logger.info("Linking: Tier 4 succeeded — found '%s' (rule_id=%s)",
                                             r.get("name"), r.get("rule_id"))
                                break
                    else:
                        logger.warning("Linking: Tier 4 failed — %s %s",
                                       find_resp.status_code, find_resp.text[:200])

                if not rule_data:
                    logger.warning(
                        "Linking: All 4 tiers failed for rule '%s' (id=%s). "
                        "Exception list created but not linked to any rule.",
                        rule_name, rule_id,
                    )

                if rule_data:
                    existing_lists = rule_data.get("exceptions_list", [])
                    # Check if already linked
                    already_linked = any(
                        el.get("list_id") == list_id for el in existing_lists
                    )
                    if not already_linked:
                        existing_lists.append({
                            "id": list_id,
                            "list_id": list_id,
                            "namespace_type": "single",
                            "type": "detection",
                        })
                        # Use the rule's own rule_id for the PATCH
                        patch_rule_id = rule_data.get("rule_id", rule_id)
                        update_resp = client.patch(
                            f"{api_prefix}/api/detection_engine/rules",
                            json={
                                "rule_id": patch_rule_id,
                                "exceptions_list": existing_lists,
                            },
                        )
                        if update_resp.status_code >= 400:
                            logger.warning(
                                "Exception list created but failed to link to rule %s: %s %s",
                                patch_rule_id, update_resp.status_code, update_resp.text[:300],
                            )
                        else:
                            rule_linked = True
                            logger.info("Exception list '%s' linked to rule '%s'", list_id, patch_rule_id)
                    else:
                        rule_linked = True
                        logger.info("Exception list '%s' already linked to rule '%s'", list_id, rule_id)
            except Exception as link_exc:
                logger.warning("Failed to link exception list to rule: %s", link_exc)

        return {
            "list_id": list_id,
            "item_id": item_data.get("id", ""),
            "status": "applied",
            "rule_linked": rule_linked,
        }

    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:500] if exc.response else "unknown"
        logger.warning("Failed to apply exception: %s %s", exc.response.status_code, body)
        return {"error": f"Kibana API error ({exc.response.status_code}): {body}", "status": "failed"}
    except Exception as exc:
        logger.warning("Exception apply failed: %s", exc)
        return {"error": str(exc), "status": "failed"}
    finally:
        client.close()
