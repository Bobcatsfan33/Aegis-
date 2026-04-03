"""
Cross-Product Analytics — Unified ClickHouse Queries Across Aegis & TokenDNA.

Correlates AI security events (aegis.ai_events), CSPM findings
(aegis.cspm_findings), and identity/auth sessions (tokendna.sessions)
to surface compound risk signals that no single product can detect alone.

Examples:
  • A user triggering guardrail violations AND authenticating from a Tor exit
  • A spike in blocked auth attempts correlating with red-team probe timing
  • Cost anomalies on a provider whose infrastructure also has CSPM findings

Requires both databases to exist on the same ClickHouse instance.
"""

import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.cross_product")

_client = None
_available = False


def _get_client():
    global _client, _available
    if _client is not None:
        return _client
    try:
        from clickhouse_driver import Client
        host = os.getenv("CLICKHOUSE_HOST", "localhost")
        port = int(os.getenv("CLICKHOUSE_PORT", "9000"))
        _client = Client(host=host, port=port, database="default")
        # Verify both databases exist
        dbs = {row[0] for row in _client.execute("SHOW DATABASES")}
        if "aegis" not in dbs:
            logger.warning("Cross-product analytics: 'aegis' database not found")
            return None
        _available = True
        logger.info("Cross-product analytics: connected to ClickHouse %s:%d", host, port)
        return _client
    except ImportError:
        logger.warning("clickhouse-driver not installed — cross-product analytics unavailable")
        return None
    except Exception as e:
        logger.warning("Cross-product analytics connection failed: %s", e)
        return None


def is_available() -> bool:
    return _get_client() is not None and _available


# ── Pre-Built Cross-Product Queries ──────────────────────────────────────────

CROSS_PRODUCT_QUERIES = {
    # Users who triggered AI guardrail violations AND had suspicious auth sessions
    "compound_risk_users": """
        SELECT
            ae.user_id,
            count(DISTINCT ae.timestamp) AS guardrail_events,
            count(DISTINCT ts.timestamp) AS suspicious_auths,
            max(ae.risk_score) AS max_ai_risk,
            max(ts.final_score) AS max_auth_score,
            groupUniqArray(ae.severity) AS ai_severities,
            groupUniqArray(ts.tier) AS auth_tiers,
            any(ts.is_tor) AS used_tor,
            any(ts.impossible_travel) AS impossible_travel
        FROM aegis.ai_events AS ae
        INNER JOIN tokendna.sessions AS ts
            ON ae.user_id = ts.user_id
            AND toDate(ae.timestamp) = toDate(ts.timestamp)
        WHERE ae.event_type = 'guardrail_event'
          AND ae.timestamp >= now() - INTERVAL 7 DAY
          AND ts.final_score >= 60
        GROUP BY ae.user_id
        HAVING guardrail_events >= 2 OR suspicious_auths >= 3
        ORDER BY max_ai_risk + max_auth_score DESC
        LIMIT 50
    """,

    # Temporal correlation: auth blocks spike when red-team probes run
    "redteam_auth_correlation": """
        SELECT
            toStartOfHour(ae.timestamp) AS hour,
            countIf(ae.event_type = 'redteam_result') AS redteam_probes,
            countIf(ae.event_type = 'guardrail_event') AS guardrail_hits,
            ts_blocks.block_count AS auth_blocks
        FROM aegis.ai_events AS ae
        LEFT JOIN (
            SELECT
                toStartOfHour(timestamp) AS hour,
                count() AS block_count
            FROM tokendna.sessions
            WHERE tier IN ('BLOCK', 'REVOKE')
              AND timestamp >= now() - INTERVAL 48 HOUR
            GROUP BY hour
        ) AS ts_blocks ON toStartOfHour(ae.timestamp) = ts_blocks.hour
        WHERE ae.timestamp >= now() - INTERVAL 48 HOUR
        GROUP BY hour, ts_blocks.block_count
        ORDER BY hour
    """,

    # Provider risk: cloud providers with CSPM findings AND AI cost anomalies
    "provider_compound_risk": """
        SELECT
            cf.provider,
            count(DISTINCT cf.scan_id) AS cspm_finding_count,
            sumIf(cf.severity = 'critical', 1, 0) AS critical_findings,
            ae_cost.total_cost,
            ae_cost.avg_latency,
            ae_cost.request_count
        FROM aegis.cspm_findings AS cf
        LEFT JOIN (
            SELECT
                provider,
                sum(cost_usd) AS total_cost,
                avg(latency_ms) AS avg_latency,
                count() AS request_count
            FROM aegis.ai_events
            WHERE event_type = 'ai_request'
              AND timestamp >= now() - INTERVAL 30 DAY
            GROUP BY provider
        ) AS ae_cost ON cf.provider = ae_cost.provider
        WHERE cf.timestamp >= now() - INTERVAL 30 DAY
        GROUP BY cf.provider, ae_cost.total_cost, ae_cost.avg_latency, ae_cost.request_count
        ORDER BY critical_findings DESC, cspm_finding_count DESC
    """,

    # Unified security timeline — all events across products in one stream
    "unified_timeline": """
        SELECT * FROM (
            SELECT
                timestamp,
                'ai_security' AS product,
                event_type AS event,
                severity,
                user_id,
                risk_score AS score,
                source AS detail
            FROM aegis.ai_events
            WHERE timestamp >= now() - INTERVAL 24 HOUR

            UNION ALL

            SELECT
                timestamp,
                'cspm' AS product,
                'finding' AS event,
                severity,
                '' AS user_id,
                0.0 AS score,
                concat(provider, ':', resource_type) AS detail
            FROM aegis.cspm_findings
            WHERE timestamp >= now() - INTERVAL 24 HOUR

            UNION ALL

            SELECT
                timestamp,
                'identity' AS product,
                tier AS event,
                CASE
                    WHEN final_score >= 80 THEN 'critical'
                    WHEN final_score >= 60 THEN 'high'
                    WHEN final_score >= 40 THEN 'medium'
                    ELSE 'low'
                END AS severity,
                user_id,
                toFloat64(final_score) AS score,
                concat(country, ':', asn) AS detail
            FROM tokendna.sessions
            WHERE timestamp >= now() - INTERVAL 24 HOUR
        )
        ORDER BY timestamp DESC
        LIMIT 1000
    """,

    # Executive summary: single row of key metrics across all products
    "executive_summary": """
        SELECT
            (SELECT count() FROM aegis.ai_events WHERE timestamp >= now() - INTERVAL 24 HOUR) AS ai_events_24h,
            (SELECT count() FROM aegis.ai_events WHERE event_type = 'guardrail_event' AND timestamp >= now() - INTERVAL 24 HOUR) AS guardrail_violations_24h,
            (SELECT sum(cost_usd) FROM aegis.ai_events WHERE event_type = 'ai_request' AND timestamp >= now() - INTERVAL 24 HOUR) AS ai_cost_24h,
            (SELECT count() FROM aegis.cspm_findings WHERE timestamp >= now() - INTERVAL 24 HOUR) AS cspm_findings_24h,
            (SELECT countIf(severity = 'critical') FROM aegis.cspm_findings WHERE timestamp >= now() - INTERVAL 24 HOUR) AS cspm_critical_24h,
            (SELECT count() FROM tokendna.sessions WHERE timestamp >= now() - INTERVAL 24 HOUR) AS auth_sessions_24h,
            (SELECT countIf(tier IN ('BLOCK', 'REVOKE')) FROM tokendna.sessions WHERE timestamp >= now() - INTERVAL 24 HOUR) AS auth_blocked_24h
    """,
}


def query(query_name: str) -> List[Dict[str, Any]]:
    """Execute a pre-built cross-product query."""
    sql = CROSS_PRODUCT_QUERIES.get(query_name)
    if not sql:
        logger.warning("Unknown cross-product query: %s", query_name)
        return []

    client = _get_client()
    if not client:
        return []

    try:
        rows = client.execute(sql)
        return [{"row": list(row)} for row in rows]
    except Exception as e:
        logger.error("Cross-product query '%s' failed: %s", query_name, e)
        return []


def query_raw(sql: str) -> List[tuple]:
    """Execute a raw cross-product SQL query."""
    client = _get_client()
    if not client:
        return []
    try:
        return client.execute(sql)
    except Exception as e:
        logger.error("Cross-product raw query failed: %s", e)
        return []


def available_queries() -> List[str]:
    """Return names of all pre-built cross-product queries."""
    return list(CROSS_PRODUCT_QUERIES.keys())
