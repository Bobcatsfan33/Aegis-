"""
ClickHouse-backed indexer for CSPM findings, remediations, and scan summaries.

This module replaces the legacy ElasticIndexer with a ClickHouse implementation,
providing superior performance for CSPM analytics workloads. ClickHouse excels at
time-series data ingestion and analytical queries over large datasets, making it
ideal for security findings indexing and trend analysis.

Migration from Elasticsearch/OpenSearch:
- ES indices → ClickHouse MergeTree tables with TTL-based retention
- JSON documents → Strongly-typed columnar schema
- Full-text search → Exact match filters + aggregations
- Real-time inserts → Batched bulk inserts with ClickHouse buffering
- Kibana dashboards → Raw SQL queries via query() and query_materialized() methods

ClickHouse advantages for this use case:
1. 10-100x faster aggregations (severity breakdown, provider stats, trends)
2. Automatic data compression (typical 10:1 ratio for security logs)
3. Built-in TTL management (automatic 365-day retention without separate jobs)
4. Materialized views for real-time aggregation (no manual aggregation tables)
5. Native support for IP/CIDR operations (future: risk-based filtering)

Configuration:
- CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DB read from config.py or env vars
- Uses native TCP protocol (clickhouse_driver) for best performance
- Database created automatically if missing
- Tables created on first access via ensure_indices()
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    from clickhouse_driver import Client
    HAS_CLICKHOUSE_DRIVER = True
except ImportError:
    HAS_CLICKHOUSE_DRIVER = False

logger = logging.getLogger(__name__)


def _get_config():
    """Load ClickHouse config from config.py or environment variables."""
    try:
        from config import CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DB
        return CLICKHOUSE_HOST, CLICKHOUSE_PORT, CLICKHOUSE_DB
    except ImportError:
        # Fall back to environment variables
        return (
            os.getenv("CLICKHOUSE_HOST", "localhost"),
            int(os.getenv("CLICKHOUSE_PORT", "9000")),
            os.getenv("CLICKHOUSE_DB", "aegis"),
        )


class ClickHouseIndexer:
    """
    Drop-in replacement for ElasticIndexer using ClickHouse as the backend.

    Provides the same public API while leveraging ClickHouse's superior
    performance for analytical queries on CSPM data.

    Public API:
    - is_available() -> bool: Check if ClickHouse is reachable
    - ensure_indices() -> None: Create tables and materialized views
    - index_scan_summary(data: dict) -> None: Index a single scan summary
    - bulk_index_scan_results(findings, remediations) -> None: Bulk index results
    - query(query_name: str) -> dict: Execute pre-built analytical query
    - query_raw(sql: str) -> List[tuple]: Execute raw SQL
    - query_materialized(view_name: str, hours: int) -> dict: Query MV results
    """

    # Pre-built analytical queries
    QUERIES = {
        "findings_by_severity": """
            SELECT
                severity,
                count() as count
            FROM {db}.cspm_findings
            WHERE timestamp >= now() - INTERVAL 7 DAY
            GROUP BY severity
            ORDER BY count DESC
        """,

        "findings_by_provider": """
            SELECT
                provider,
                count() as count
            FROM {db}.cspm_findings
            WHERE timestamp >= now() - INTERVAL 30 DAY
            GROUP BY provider
            ORDER BY count DESC
        """,

        "findings_over_time": """
            SELECT
                toStartOfHour(timestamp) as hour,
                count() as count
            FROM {db}.cspm_findings
            WHERE timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour
        """,

        "findings_by_resource_type": """
            SELECT
                resource_type,
                count() as count
            FROM {db}.cspm_findings
            WHERE timestamp >= now() - INTERVAL 30 DAY
            GROUP BY resource_type
            ORDER BY count DESC
            LIMIT 20
        """,

        "remediation_success_rate": """
            SELECT
                tool,
                countIf(action_taken = 'success') as success_count,
                count() as total_count,
                round(countIf(action_taken = 'success') * 100.0 / count(), 2) as success_rate
            FROM {db}.cspm_remediations
            WHERE timestamp >= now() - INTERVAL 30 DAY
            GROUP BY tool
            ORDER BY success_rate DESC
        """,

        "scan_trend": """
            SELECT
                toDate(timestamp) as scan_date,
                count(DISTINCT scan_id) as scan_count,
                sum(total_findings) as total_findings
            FROM {db}.cspm_scans
            WHERE timestamp >= now() - INTERVAL 30 DAY
            GROUP BY scan_date
            ORDER BY scan_date
        """,
    }

    def __init__(self):
        """Initialize ClickHouse client and configuration."""
        self.host, self.port, self.db = _get_config()
        self.client: Optional[Client] = None
        self._tables_created = False

        if not HAS_CLICKHOUSE_DRIVER:
            logger.warning(
                "clickhouse_driver not installed; ClickHouseIndexer will be unavailable. "
                "Install with: pip install clickhouse-driver"
            )
            return

        try:
            self.client = Client(
                host=self.host,
                port=self.port,
                database=self.db,
                settings={"max_insert_threads": 4},
            )
            logger.info(
                f"ClickHouseIndexer initialized: {self.host}:{self.port}/{self.db}"
            )
        except Exception as e:
            logger.warning(
                f"Failed to connect to ClickHouse at {self.host}:{self.port}: {e}"
            )
            self.client = None

    def is_available(self) -> bool:
        """Check if ClickHouse is reachable and responsive."""
        if not HAS_CLICKHOUSE_DRIVER or self.client is None:
            return False

        try:
            self.client.execute("SELECT 1")
            return True
        except Exception as e:
            logger.warning(f"ClickHouse health check failed: {e}")
            return False

    def ensure_indices(self) -> None:
        """
        Create ClickHouse tables and materialized views if they don't exist.

        Tables created:
        1. cspm_findings: MergeTree with monthly partitioning and 365-day TTL
        2. cspm_remediations: MergeTree with monthly partitioning and 365-day TTL
        3. cspm_scans: MergeTree with daily partitioning and 365-day TTL

        Materialized views:
        1. cspm_findings_by_severity_mv: Real-time hourly aggregation by severity
        2. cspm_findings_by_provider_mv: Real-time hourly aggregation by provider
        3. cspm_remediation_rate_mv: Real-time hourly success/fail tracking by tool
        """
        if not self.is_available():
            logger.warning("ClickHouse unavailable; skipping index creation")
            return

        if self._tables_created:
            return

        try:
            # Ensure database exists
            self.client.execute(f"CREATE DATABASE IF NOT EXISTS {self.db}")

            # Create cspm_findings table
            self.client.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.db}.cspm_findings (
                    finding_id String,
                    scan_id String,
                    timestamp DateTime DEFAULT now(),
                    severity LowCardinality(String),
                    provider LowCardinality(String),
                    region LowCardinality(String),
                    resource_id String,
                    resource_type LowCardinality(String),
                    resource_name String,
                    description String,
                    remediation_text String,
                    finding_metadata String,
                    INDEX finding_id_idx finding_id TYPE hash GRANULARITY 8192,
                    INDEX scan_id_idx scan_id TYPE hash GRANULARITY 8192,
                    INDEX severity_idx severity TYPE set(10) GRANULARITY 1,
                    INDEX provider_idx provider TYPE set(10) GRANULARITY 1
                ) ENGINE = MergeTree()
                PARTITION BY toYYYYMM(timestamp)
                ORDER BY (severity, provider, timestamp)
                TTL timestamp + INTERVAL 365 DAY
                SETTINGS storage_policy = 'default'
            """)
            logger.info("Created cspm_findings table")

            # Create cspm_remediations table
            self.client.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.db}.cspm_remediations (
                    remediation_id String,
                    scan_id String,
                    finding_id String,
                    timestamp DateTime DEFAULT now(),
                    tool LowCardinality(String),
                    action_taken LowCardinality(String),
                    action_status String,
                    action_message String,
                    INDEX scan_id_idx scan_id TYPE hash GRANULARITY 8192,
                    INDEX finding_id_idx finding_id TYPE hash GRANULARITY 8192,
                    INDEX tool_idx tool TYPE set(10) GRANULARITY 1,
                    INDEX action_idx action_taken TYPE set(10) GRANULARITY 1
                ) ENGINE = MergeTree()
                PARTITION BY toYYYYMM(timestamp)
                ORDER BY (scan_id, timestamp)
                TTL timestamp + INTERVAL 365 DAY
                SETTINGS storage_policy = 'default'
            """)
            logger.info("Created cspm_remediations table")

            # Create cspm_scans table
            self.client.execute(f"""
                CREATE TABLE IF NOT EXISTS {self.db}.cspm_scans (
                    scan_id String,
                    timestamp DateTime DEFAULT now(),
                    scan_type String,
                    total_findings UInt32,
                    critical_count UInt32,
                    high_count UInt32,
                    medium_count UInt32,
                    low_count UInt32,
                    scan_duration_seconds UInt32,
                    INDEX scan_id_idx scan_id TYPE hash GRANULARITY 8192
                ) ENGINE = MergeTree()
                PARTITION BY toYYYYMM(timestamp)
                ORDER BY (timestamp)
                TTL timestamp + INTERVAL 365 DAY
                SETTINGS storage_policy = 'default'
            """)
            logger.info("Created cspm_scans table")

            # Create materialized view: findings_by_severity
            self._create_findings_by_severity_mv()

            # Create materialized view: findings_by_provider
            self._create_findings_by_provider_mv()

            # Create materialized view: remediation_rate
            self._create_remediation_rate_mv()

            self._tables_created = True
            logger.info("All ClickHouse indices and materialized views created successfully")

        except Exception as e:
            logger.error(f"Failed to create ClickHouse indices: {e}")
            raise

    def _create_findings_by_severity_mv(self) -> None:
        """Create materialized view for findings aggregated by severity."""
        db = self.db

        # Create destination table
        self.client.execute(f"""
            CREATE TABLE IF NOT EXISTS {db}.cspm_findings_by_severity_mv (
                hour DateTime,
                severity LowCardinality(String),
                count AggregateFunction(sum, UInt32)
            ) ENGINE = AggregatingMergeTree()
            ORDER BY (hour, severity)
            TTL hour + INTERVAL 60 DAY
        """)

        # Create materialized view
        self.client.execute(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.cspm_findings_by_severity_mv_insert
            TO {db}.cspm_findings_by_severity_mv AS
            SELECT
                toStartOfHour(timestamp) as hour,
                severity,
                sumState(CAST(1 AS UInt32)) as count
            FROM {db}.cspm_findings
            GROUP BY hour, severity
        """)

        logger.info("Created findings_by_severity materialized view")

    def _create_findings_by_provider_mv(self) -> None:
        """Create materialized view for findings aggregated by provider."""
        db = self.db

        # Create destination table
        self.client.execute(f"""
            CREATE TABLE IF NOT EXISTS {db}.cspm_findings_by_provider_mv (
                hour DateTime,
                provider LowCardinality(String),
                count AggregateFunction(sum, UInt32)
            ) ENGINE = AggregatingMergeTree()
            ORDER BY (hour, provider)
            TTL hour + INTERVAL 60 DAY
        """)

        # Create materialized view
        self.client.execute(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.cspm_findings_by_provider_mv_insert
            TO {db}.cspm_findings_by_provider_mv AS
            SELECT
                toStartOfHour(timestamp) as hour,
                provider,
                sumState(CAST(1 AS UInt32)) as count
            FROM {db}.cspm_findings
            GROUP BY hour, provider
        """)

        logger.info("Created findings_by_provider materialized view")

    def _create_remediation_rate_mv(self) -> None:
        """Create materialized view for remediation success/fail rates by tool."""
        db = self.db

        # Create destination table
        self.client.execute(f"""
            CREATE TABLE IF NOT EXISTS {db}.cspm_remediation_rate_mv (
                hour DateTime,
                tool LowCardinality(String),
                action_taken LowCardinality(String),
                count AggregateFunction(sum, UInt32)
            ) ENGINE = AggregatingMergeTree()
            ORDER BY (hour, tool, action_taken)
            TTL hour + INTERVAL 60 DAY
        """)

        # Create materialized view
        self.client.execute(f"""
            CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.cspm_remediation_rate_mv_insert
            TO {db}.cspm_remediation_rate_mv AS
            SELECT
                toStartOfHour(timestamp) as hour,
                tool,
                action_taken,
                sumState(CAST(1 AS UInt32)) as count
            FROM {db}.cspm_remediations
            GROUP BY hour, tool, action_taken
        """)

        logger.info("Created remediation_rate materialized view")

    def index_scan_summary(self, data: Dict[str, Any]) -> None:
        """
        Index a single scan summary record.

        Args:
            data: Dictionary with keys:
                - scan_id (str): Unique scan identifier
                - timestamp (datetime or str): Scan start time
                - scan_type (str): Type of scan (e.g., 'aws_security_hub', 'azure_policy')
                - total_findings (int): Total findings in this scan
                - critical_count (int): Number of critical findings
                - high_count (int): Number of high findings
                - medium_count (int): Number of medium findings
                - low_count (int): Number of low findings
                - scan_duration_seconds (int): Duration of scan in seconds
        """
        if not self.is_available():
            logger.warning("ClickHouse unavailable; skipping scan summary indexing")
            return

        try:
            timestamp = data.get("timestamp")
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)

            self.client.execute(
                f"""
                INSERT INTO {self.db}.cspm_scans (
                    scan_id, timestamp, scan_type, total_findings,
                    critical_count, high_count, medium_count, low_count,
                    scan_duration_seconds
                ) VALUES
                """,
                [(
                    data.get("scan_id"),
                    timestamp,
                    data.get("scan_type"),
                    data.get("total_findings", 0),
                    data.get("critical_count", 0),
                    data.get("high_count", 0),
                    data.get("medium_count", 0),
                    data.get("low_count", 0),
                    data.get("scan_duration_seconds", 0),
                )]
            )
            logger.debug(f"Indexed scan summary: {data.get('scan_id')}")
        except Exception as e:
            logger.error(f"Failed to index scan summary: {e}")

    def bulk_index_scan_results(
        self,
        findings: List[Dict[str, Any]],
        remediations: List[Dict[str, Any]],
    ) -> None:
        """
        Bulk index findings and remediations from a scan.

        Args:
            findings: List of finding records with keys:
                - finding_id, scan_id, timestamp, severity, provider, region,
                  resource_id, resource_type, resource_name, description,
                  remediation_text, finding_metadata

            remediations: List of remediation records with keys:
                - remediation_id, scan_id, finding_id, timestamp, tool,
                  action_taken, action_status, action_message
        """
        if not self.is_available():
            logger.warning("ClickHouse unavailable; skipping bulk indexing")
            return

        try:
            # Bulk insert findings
            if findings:
                finding_rows = []
                for f in findings:
                    timestamp = f.get("timestamp")
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp)

                    finding_rows.append((
                        f.get("finding_id"),
                        f.get("scan_id"),
                        timestamp,
                        f.get("severity", "UNKNOWN"),
                        f.get("provider", "UNKNOWN"),
                        f.get("region", "unknown"),
                        f.get("resource_id"),
                        f.get("resource_type", "unknown"),
                        f.get("resource_name", ""),
                        f.get("description", ""),
                        f.get("remediation_text", ""),
                        json.dumps(f.get("finding_metadata", {})),
                    ))

                self.client.execute(
                    f"""
                    INSERT INTO {self.db}.cspm_findings (
                        finding_id, scan_id, timestamp, severity, provider, region,
                        resource_id, resource_type, resource_name, description,
                        remediation_text, finding_metadata
                    ) VALUES
                    """,
                    finding_rows,
                )
                logger.debug(f"Bulk indexed {len(findings)} findings")

            # Bulk insert remediations
            if remediations:
                remediation_rows = []
                for r in remediations:
                    timestamp = r.get("timestamp")
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp)

                    remediation_rows.append((
                        r.get("remediation_id"),
                        r.get("scan_id"),
                        r.get("finding_id"),
                        timestamp,
                        r.get("tool", "unknown"),
                        r.get("action_taken", "unknown"),
                        r.get("action_status", ""),
                        r.get("action_message", ""),
                    ))

                self.client.execute(
                    f"""
                    INSERT INTO {self.db}.cspm_remediations (
                        remediation_id, scan_id, finding_id, timestamp, tool,
                        action_taken, action_status, action_message
                    ) VALUES
                    """,
                    remediation_rows,
                )
                logger.debug(f"Bulk indexed {len(remediations)} remediations")

        except Exception as e:
            logger.error(f"Failed to bulk index scan results: {e}")

    def query(self, query_name: str) -> Dict[str, Any]:
        """
        Execute a pre-built analytical query.

        Args:
            query_name: Name of the query (e.g., 'findings_by_severity')

        Returns:
            Dictionary with 'data' key containing results and optional 'error' key
        """
        if query_name not in self.QUERIES:
            return {"error": f"Unknown query: {query_name}"}

        try:
            sql = self.QUERIES[query_name].format(db=self.db)
            results = self.query_raw(sql)

            # Convert to list of dicts based on query name
            if query_name == "findings_by_severity":
                data = [{"severity": r[0], "count": r[1]} for r in results]
            elif query_name == "findings_by_provider":
                data = [{"provider": r[0], "count": r[1]} for r in results]
            elif query_name == "findings_over_time":
                data = [{"hour": r[0].isoformat(), "count": r[1]} for r in results]
            elif query_name == "findings_by_resource_type":
                data = [{"resource_type": r[0], "count": r[1]} for r in results]
            elif query_name == "remediation_success_rate":
                data = [{
                    "tool": r[0],
                    "success_count": r[1],
                    "total_count": r[2],
                    "success_rate": r[3],
                } for r in results]
            elif query_name == "scan_trend":
                data = [{
                    "scan_date": r[0].isoformat(),
                    "scan_count": r[1],
                    "total_findings": r[2],
                } for r in results]
            else:
                data = results

            return {"data": data}
        except Exception as e:
            logger.error(f"Query failed: {query_name}: {e}")
            return {"error": str(e)}

    def query_raw(self, sql: str) -> List[Tuple]:
        """
        Execute raw SQL query against ClickHouse.

        Args:
            sql: SQL query string

        Returns:
            List of tuples representing rows
        """
        if not self.is_available():
            logger.warning("ClickHouse unavailable; returning empty results")
            return []

        try:
            return self.client.execute(sql)
        except Exception as e:
            logger.error(f"Raw query failed: {e}")
            return []

    def query_materialized(
        self,
        view_name: str,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Query materialized view results with optional time filtering.

        Args:
            view_name: Name of materialized view ('findings_by_severity',
                      'findings_by_provider', 'remediation_rate')
            hours: Number of hours to look back (default: 24)

        Returns:
            Dictionary with 'data' key or 'error' key
        """
        if view_name == "findings_by_severity":
            table = f"{self.db}.cspm_findings_by_severity_mv"
            sql = f"""
                SELECT
                    hour,
                    severity,
                    sumMerge(count) as count
                FROM {table}
                WHERE hour >= now() - INTERVAL {hours} HOUR
                GROUP BY hour, severity
                ORDER BY hour DESC, severity
            """
            try:
                results = self.query_raw(sql)
                data = [{
                    "hour": r[0].isoformat(),
                    "severity": r[1],
                    "count": r[2],
                } for r in results]
                return {"data": data}
            except Exception as e:
                logger.error(f"Materialized view query failed: {e}")
                return {"error": str(e)}

        elif view_name == "findings_by_provider":
            table = f"{self.db}.cspm_findings_by_provider_mv"
            sql = f"""
                SELECT
                    hour,
                    provider,
                    sumMerge(count) as count
                FROM {table}
                WHERE hour >= now() - INTERVAL {hours} HOUR
                GROUP BY hour, provider
                ORDER BY hour DESC, provider
            """
            try:
                results = self.query_raw(sql)
                data = [{
                    "hour": r[0].isoformat(),
                    "provider": r[1],
                    "count": r[2],
                } for r in results]
                return {"data": data}
            except Exception as e:
                logger.error(f"Materialized view query failed: {e}")
                return {"error": str(e)}

        elif view_name == "remediation_rate":
            table = f"{self.db}.cspm_remediation_rate_mv"
            sql = f"""
                SELECT
                    hour,
                    tool,
                    action_taken,
                    sumMerge(count) as count
                FROM {table}
                WHERE hour >= now() - INTERVAL {hours} HOUR
                GROUP BY hour, tool, action_taken
                ORDER BY hour DESC, tool, action_taken
            """
            try:
                results = self.query_raw(sql)
                data = [{
                    "hour": r[0].isoformat(),
                    "tool": r[1],
                    "action_taken": r[2],
                    "count": r[3],
                } for r in results]
                return {"data": data}
            except Exception as e:
                logger.error(f"Materialized view query failed: {e}")
                return {"error": str(e)}

        else:
            return {"error": f"Unknown materialized view: {view_name}"}


# Graceful degradation: create a dummy indexer if ClickHouse is unavailable
class DummyClickHouseIndexer:
    """Fallback indexer that logs warnings and returns defaults."""

    def is_available(self) -> bool:
        return False

    def ensure_indices(self) -> None:
        logger.warning("DummyClickHouseIndexer: ClickHouse not available")

    def index_scan_summary(self, data: Dict[str, Any]) -> None:
        logger.warning("DummyClickHouseIndexer: index_scan_summary called but unavailable")

    def bulk_index_scan_results(
        self,
        findings: List[Dict[str, Any]],
        remediations: List[Dict[str, Any]],
    ) -> None:
        logger.warning("DummyClickHouseIndexer: bulk_index_scan_results called but unavailable")

    def query(self, query_name: str) -> Dict[str, Any]:
        return {"error": "ClickHouse unavailable", "data": []}

    def query_raw(self, sql: str) -> List[Tuple]:
        return []

    def query_materialized(
        self,
        view_name: str,
        hours: int = 24,
    ) -> Dict[str, Any]:
        return {"error": "ClickHouse unavailable", "data": []}


def get_indexer() -> Any:
    """
    Factory function to get the appropriate indexer instance.

    Returns ClickHouseIndexer if available, otherwise DummyClickHouseIndexer
    for graceful degradation.
    """
    indexer = ClickHouseIndexer()
    if indexer.is_available():
        return indexer
    else:
        logger.warning("ClickHouse unavailable; using DummyClickHouseIndexer")
        return DummyClickHouseIndexer()
