"""
AI Telemetry & Analytics — v3.0.0

High-throughput event ingestion pipeline for all AI security events.
Primary backend: ClickHouse (columnar, sub-second analytics on billions of rows).
Fallback: OpenSearch (already in stack).  Supports batched inserts, schema
auto-migration, and pre-built analytical queries for dashboards.

NIST 800-53: AU-2 (Event Logging), AU-6 (Audit Record Review/Analysis),
AU-12 (Audit Record Generation), SI-4 (System Monitoring).
"""

from modules.telemetry.engine import TelemetryEngine, AIEvent, EventType

__all__ = ["TelemetryEngine", "AIEvent", "EventType"]
