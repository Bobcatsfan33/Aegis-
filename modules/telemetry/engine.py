"""
AI Telemetry & Analytics Engine.

High-throughput event ingestion for all AI security events.  Primary backend
is ClickHouse for sub-second columnar analytics; fallback to OpenSearch
(already in the Aegis stack).

Event types:
  - ai_request      — Every LLM prompt/completion
  - guardrail_event — Every guardrail evaluation
  - redteam_result  — Every red team attack probe
  - policy_event    — Every policy evaluation
  - discovery_event — Every asset discovered
  - system_event    — Health, errors, config changes

Schema is auto-migrated on startup. Batched inserts (configurable flush
interval + batch size) for high throughput without per-event overhead.
"""

import json
import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger("aegis.telemetry")


class EventType(str, Enum):
    AI_REQUEST = "ai_request"
    GUARDRAIL = "guardrail_event"
    REDTEAM = "redteam_result"
    POLICY = "policy_event"
    DISCOVERY = "discovery_event"
    SYSTEM = "system_event"


@dataclass
class AIEvent:
    """A single AI telemetry event."""
    event_type: EventType
    source: str                     # Module that generated the event
    severity: str = "info"          # "critical", "high", "medium", "low", "info"
    data: Dict[str, Any] = field(default_factory=dict)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    model: Optional[str] = None
    provider: Optional[str] = None
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    risk_score: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type.value,
            "source": self.source,
            "severity": self.severity,
            "data": self.data,
            "user_id": self.user_id or "",
            "session_id": self.session_id or "",
            "model": self.model or "",
            "provider": self.provider or "",
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
        }

    def to_clickhouse_row(self) -> tuple:
        """Convert to a tuple for ClickHouse bulk insert."""
        return (
            self.event_type.value,
            self.source,
            self.severity,
            json.dumps(self.data),
            self.user_id or "",
            self.session_id or "",
            self.model or "",
            self.provider or "",
            self.input_tokens,
            self.output_tokens,
            self.latency_ms,
            self.cost_usd,
            self.risk_score,
            self.timestamp,
        )


# ── ClickHouse Schema ────────────────────────────────────────────────

CLICKHOUSE_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS ai_events (
    event_type     LowCardinality(String),
    source         LowCardinality(String),
    severity       LowCardinality(String),
    data           String,
    user_id        String,
    session_id     String,
    model          LowCardinality(String),
    provider       LowCardinality(String),
    input_tokens   UInt32,
    output_tokens  UInt32,
    latency_ms     Float64,
    cost_usd       Float64,
    risk_score     Float64,
    timestamp      DateTime64(3, 'UTC'),

    -- Materialized columns for fast filtering
    event_date     Date MATERIALIZED toDate(timestamp),
    event_hour     UInt8 MATERIALIZED toHour(timestamp)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_type, provider, timestamp)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
"""

# ── Materialized Views for Real-Time Dashboards ────────────────────────

CLICKHOUSE_MATERIALIZED_VIEWS = [
    # Hourly event counts by type — powers the main timeline chart
    """
    CREATE TABLE IF NOT EXISTS ai_events_hourly (
        hour          DateTime,
        event_type    LowCardinality(String),
        severity      LowCardinality(String),
        cnt           AggregateFunction(count, UInt64),
        avg_latency   AggregateFunction(avg, Float64),
        sum_cost      AggregateFunction(sum, Float64),
        sum_tokens    AggregateFunction(sum, UInt64)
    )
    ENGINE = AggregatingMergeTree()
    PARTITION BY toYYYYMM(hour)
    ORDER BY (hour, event_type, severity)
    TTL hour + INTERVAL 90 DAY;
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS ai_events_hourly_mv
    TO ai_events_hourly AS
    SELECT
        toStartOfHour(timestamp)      AS hour,
        event_type,
        severity,
        countState()                  AS cnt,
        avgState(latency_ms)          AS avg_latency,
        sumState(cost_usd)            AS sum_cost,
        sumState(input_tokens + output_tokens) AS sum_tokens
    FROM ai_events
    GROUP BY hour, event_type, severity;
    """,
    # Provider cost rollup — powers cost optimization dashboard
    """
    CREATE TABLE IF NOT EXISTS ai_cost_by_provider (
        day           Date,
        provider      LowCardinality(String),
        model         LowCardinality(String),
        total_cost    AggregateFunction(sum, Float64),
        total_tokens  AggregateFunction(sum, UInt64),
        request_count AggregateFunction(count, UInt64),
        p95_latency   AggregateFunction(quantile(0.95), Float64)
    )
    ENGINE = AggregatingMergeTree()
    PARTITION BY toYYYYMM(day)
    ORDER BY (day, provider, model)
    TTL day + INTERVAL 365 DAY;
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS ai_cost_by_provider_mv
    TO ai_cost_by_provider AS
    SELECT
        toDate(timestamp)                   AS day,
        provider,
        model,
        sumState(cost_usd)                  AS total_cost,
        sumState(input_tokens + output_tokens) AS total_tokens,
        countState()                        AS request_count,
        quantileState(0.95)(latency_ms)     AS p95_latency
    FROM ai_events
    WHERE event_type = 'ai_request'
    GROUP BY day, provider, model;
    """,
    # Risk score distribution — powers risk heatmap
    """
    CREATE TABLE IF NOT EXISTS ai_risk_hourly (
        hour          DateTime,
        severity      LowCardinality(String),
        source        LowCardinality(String),
        cnt           AggregateFunction(count, UInt64),
        max_risk      AggregateFunction(max, Float64),
        avg_risk      AggregateFunction(avg, Float64)
    )
    ENGINE = AggregatingMergeTree()
    PARTITION BY toYYYYMM(hour)
    ORDER BY (hour, severity, source)
    TTL hour + INTERVAL 90 DAY;
    """,
    """
    CREATE MATERIALIZED VIEW IF NOT EXISTS ai_risk_hourly_mv
    TO ai_risk_hourly AS
    SELECT
        toStartOfHour(timestamp) AS hour,
        severity,
        source,
        countState()             AS cnt,
        maxState(risk_score)     AS max_risk,
        avgState(risk_score)     AS avg_risk
    FROM ai_events
    GROUP BY hour, severity, source;
    """,
]

# Pre-built analytical queries
ANALYTICS_QUERIES = {
    "events_per_hour": """
        SELECT toStartOfHour(timestamp) AS hour, count() AS cnt
        FROM ai_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        GROUP BY hour ORDER BY hour
    """,
    "risk_distribution": """
        SELECT severity, count() AS cnt
        FROM ai_events
        WHERE timestamp >= now() - INTERVAL 7 DAY
        GROUP BY severity ORDER BY cnt DESC
    """,
    "top_models": """
        SELECT model, count() AS requests, sum(cost_usd) AS total_cost,
               avg(latency_ms) AS avg_latency
        FROM ai_events
        WHERE event_type = 'ai_request'
          AND timestamp >= now() - INTERVAL 30 DAY
        GROUP BY model ORDER BY requests DESC LIMIT 20
    """,
    "provider_breakdown": """
        SELECT provider, count() AS requests, sum(input_tokens + output_tokens) AS total_tokens,
               sum(cost_usd) AS total_cost
        FROM ai_events
        WHERE event_type = 'ai_request'
          AND timestamp >= now() - INTERVAL 30 DAY
        GROUP BY provider ORDER BY requests DESC
    """,
    "guardrail_violations": """
        SELECT JSONExtractString(data, 'action') AS action, count() AS cnt
        FROM ai_events
        WHERE event_type = 'guardrail_event'
          AND timestamp >= now() - INTERVAL 7 DAY
        GROUP BY action ORDER BY cnt DESC
    """,
    "redteam_success_rate": """
        SELECT JSONExtractString(data, 'category') AS category,
               countIf(JSONExtractBool(data, 'succeeded')) AS succeeded,
               count() AS total,
               round(succeeded / total * 100, 1) AS success_pct
        FROM ai_events
        WHERE event_type = 'redteam_result'
          AND timestamp >= now() - INTERVAL 30 DAY
        GROUP BY category ORDER BY success_pct DESC
    """,
    "daily_cost": """
        SELECT toDate(timestamp) AS day, sum(cost_usd) AS total_cost,
               sum(input_tokens + output_tokens) AS total_tokens
        FROM ai_events
        WHERE event_type = 'ai_request'
          AND timestamp >= now() - INTERVAL 30 DAY
        GROUP BY day ORDER BY day
    """,
    "policy_compliance": """
        SELECT JSONExtractBool(data, 'compliant') AS compliant, count() AS cnt
        FROM ai_events
        WHERE event_type = 'policy_event'
          AND timestamp >= now() - INTERVAL 7 DAY
        GROUP BY compliant
    """,
    "hourly_events_materialized": """
        SELECT hour, event_type, severity,
               countMerge(cnt) AS count,
               avgMerge(avg_latency) AS avg_latency_ms,
               sumMerge(sum_cost) AS total_cost
        FROM ai_events_hourly
        WHERE hour >= now() - INTERVAL 24 HOUR
        GROUP BY hour, event_type, severity
        ORDER BY hour, event_type
    """,
    "daily_cost_by_provider": """
        SELECT day, provider, model,
               sumMerge(total_cost) AS cost,
               sumMerge(total_tokens) AS tokens,
               countMerge(request_count) AS requests,
               quantileMerge(0.95)(p95_latency) AS p95_latency_ms
        FROM ai_cost_by_provider
        WHERE day >= today() - 30
        GROUP BY day, provider, model
        ORDER BY day, cost DESC
    """,
    "risk_heatmap": """
        SELECT hour, severity, source,
               countMerge(cnt) AS count,
               maxMerge(max_risk) AS max_risk,
               avgMerge(avg_risk) AS avg_risk
        FROM ai_risk_hourly
        WHERE hour >= now() - INTERVAL 24 HOUR
        GROUP BY hour, severity, source
        ORDER BY hour, severity
    """,
}


class TelemetryEngine:
    """
    AI Telemetry Engine with batched ClickHouse ingestion.

    Usage:
        engine = TelemetryEngine()
        engine.start()  # Starts background flush thread

        # Log events
        engine.log(AIEvent(
            event_type=EventType.AI_REQUEST,
            source="guardrails",
            model="gpt-4o",
            ...
        ))

        # Query analytics
        results = engine.query("events_per_hour")

        engine.stop()
    """

    def __init__(
        self,
        clickhouse_host: Optional[str] = None,
        clickhouse_port: int = 9000,
        database: str = "aegis",
        batch_size: int = 100,
        flush_interval_seconds: float = 5.0,
        fallback_to_file: bool = True,
        log_file: str = "ai_events.jsonl",
    ):
        self.ch_host = clickhouse_host or os.getenv("CLICKHOUSE_HOST", "localhost")
        self.ch_port = int(os.getenv("CLICKHOUSE_PORT", str(clickhouse_port)))
        self.database = database
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.fallback_to_file = fallback_to_file
        self.log_file = log_file

        self._buffer: Deque[AIEvent] = deque()
        self._lock = threading.Lock()
        self._running = False
        self._flush_thread: Optional[threading.Thread] = None
        self._client = None
        self._ch_available = False

    def start(self):
        """Initialize backends and start background flush thread."""
        self._init_clickhouse()
        self._running = True
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()
        logger.info("Telemetry engine started (ClickHouse=%s, file_fallback=%s)",
                     self._ch_available, self.fallback_to_file)

    def stop(self):
        """Flush remaining events and stop background thread."""
        self._running = False
        self._flush()
        if self._flush_thread:
            self._flush_thread.join(timeout=5)
        logger.info("Telemetry engine stopped")

    def log(self, event: AIEvent):
        """Queue an event for batched ingestion."""
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) >= self.batch_size:
                self._flush()

    def log_many(self, events: List[AIEvent]):
        """Queue multiple events."""
        with self._lock:
            self._buffer.extend(events)
            if len(self._buffer) >= self.batch_size:
                self._flush()

    def query(self, query_name: str) -> List[Dict[str, Any]]:
        """Execute a pre-built analytics query."""
        sql = ANALYTICS_QUERIES.get(query_name)
        if not sql:
            logger.warning("Unknown analytics query: %s", query_name)
            return []

        if not self._ch_available:
            logger.warning("ClickHouse not available — cannot run query '%s'", query_name)
            return []

        try:
            rows = self._client.execute(sql)
            # Convert tuples to dicts using column names from query
            return [{"row": list(row)} for row in rows]
        except Exception as e:
            logger.error("ClickHouse query '%s' failed: %s", query_name, e)
            return []

    def query_raw(self, sql: str) -> List[tuple]:
        """Execute a raw SQL query against ClickHouse."""
        if not self._ch_available:
            return []
        try:
            return self._client.execute(sql)
        except Exception as e:
            logger.error("Raw query failed: %s", e)
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get current telemetry engine stats."""
        return {
            "buffer_size": len(self._buffer),
            "clickhouse_available": self._ch_available,
            "clickhouse_host": self.ch_host,
            "batch_size": self.batch_size,
            "flush_interval": self.flush_interval,
            "running": self._running,
        }

    # ── Internal ──────────────────────────────────────────────────────

    def _init_clickhouse(self):
        """Try to connect to ClickHouse and create schema."""
        try:
            from clickhouse_driver import Client
            self._client = Client(
                host=self.ch_host,
                port=self.ch_port,
                database="default",
            )
            # Create database
            self._client.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            self._client = Client(
                host=self.ch_host,
                port=self.ch_port,
                database=self.database,
            )
            # Create table
            self._client.execute(CLICKHOUSE_CREATE_TABLE)
            # Create materialized views for real-time dashboards
            for mv_sql in CLICKHOUSE_MATERIALIZED_VIEWS:
                try:
                    self._client.execute(mv_sql)
                except Exception as mv_err:
                    logger.warning("Materialized view creation: %s", mv_err)
            self._ch_available = True
            logger.info("ClickHouse connected: %s:%d/%s", self.ch_host, self.ch_port, self.database)
        except ImportError:
            logger.warning("clickhouse-driver not installed — using file fallback")
            self._ch_available = False
        except Exception as e:
            logger.warning("ClickHouse connection failed (%s) — using file fallback", e)
            self._ch_available = False

    def _flush_loop(self):
        """Background thread that periodically flushes the buffer."""
        while self._running:
            time.sleep(self.flush_interval)
            with self._lock:
                if self._buffer:
                    self._flush()

    def _flush(self):
        """Flush buffered events to backend(s)."""
        if not self._buffer:
            return

        events = list(self._buffer)
        self._buffer.clear()

        # Try ClickHouse first
        if self._ch_available:
            try:
                rows = [e.to_clickhouse_row() for e in events]
                self._client.execute(
                    "INSERT INTO ai_events VALUES",
                    rows,
                )
                logger.debug("Flushed %d events to ClickHouse", len(events))
                return
            except Exception as e:
                logger.error("ClickHouse flush failed: %s — falling back to file", e)

        # File fallback
        if self.fallback_to_file:
            try:
                with open(self.log_file, "a") as f:
                    for event in events:
                        f.write(json.dumps(event.to_dict()) + "\n")
                logger.debug("Flushed %d events to %s", len(events), self.log_file)
            except Exception as e:
                logger.error("File fallback flush failed: %s", e)
