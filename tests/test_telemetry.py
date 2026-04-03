"""
Unit tests for AegisAI Telemetry Engine.

Tests event ingestion, batching, ClickHouse integration (mocked), file fallback,
background flush thread, analytics queries, and engine lifecycle.
"""

import json
import os
import sys
import tempfile
import threading
import time
from unittest.mock import MagicMock, patch, mock_open, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.telemetry.engine import (
    TelemetryEngine,
    AIEvent,
    EventType,
    ANALYTICS_QUERIES,
    CLICKHOUSE_CREATE_TABLE,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def engine_no_ch(tmp_path):
    """Engine with ClickHouse disabled and file fallback enabled."""
    return TelemetryEngine(
        clickhouse_host="localhost",
        batch_size=100,
        flush_interval_seconds=60.0,
        fallback_to_file=True,
        log_file=str(tmp_path / "events.jsonl"),
    )


@pytest.fixture
def ai_event():
    """A sample AI request event."""
    return AIEvent(
        event_type=EventType.AI_REQUEST,
        source="test",
        severity="info",
        data={"prompt_length": 50},
        model="gpt-4o",
        provider="openai",
        input_tokens=100,
        output_tokens=50,
        latency_ms=250.0,
        cost_usd=0.002,
        risk_score=0.0,
        user_id="user-123",
        session_id="sess-abc",
    )


@pytest.fixture
def guardrail_event():
    return AIEvent(
        event_type=EventType.GUARDRAIL,
        source="guardrails",
        severity="high",
        data={"action": "redact", "violation_count": 2},
        risk_score=0.6,
    )


# ── AIEvent Model ─────────────────────────────────────────────────────────────


class TestAIEventModel:
    """Tests for the AIEvent dataclass."""

    def test_to_dict_fields(self, ai_event):
        d = ai_event.to_dict()
        assert d["event_type"] == "ai_request"
        assert d["source"] == "test"
        assert d["severity"] == "info"
        assert d["model"] == "gpt-4o"
        assert d["provider"] == "openai"
        assert d["input_tokens"] == 100
        assert d["output_tokens"] == 50
        assert d["latency_ms"] == 250.0
        assert d["cost_usd"] == 0.002
        assert d["risk_score"] == 0.0
        assert d["user_id"] == "user-123"
        assert d["session_id"] == "sess-abc"
        assert "timestamp" in d
        assert "data" in d

    def test_to_dict_optional_fields_default_empty(self):
        event = AIEvent(event_type=EventType.SYSTEM, source="test")
        d = event.to_dict()
        assert d["user_id"] == ""
        assert d["session_id"] == ""
        assert d["model"] == ""
        assert d["provider"] == ""

    def test_to_clickhouse_row(self, ai_event):
        row = ai_event.to_clickhouse_row()
        assert isinstance(row, tuple)
        assert len(row) == 14
        assert row[0] == "ai_request"   # event_type
        assert row[1] == "test"          # source
        assert row[6] == "gpt-4o"        # model
        assert row[7] == "openai"        # provider
        assert row[8] == 100             # input_tokens
        assert row[9] == 50              # output_tokens

    def test_clickhouse_row_data_is_json(self, ai_event):
        row = ai_event.to_clickhouse_row()
        data_field = row[3]
        parsed = json.loads(data_field)
        assert parsed["prompt_length"] == 50

    def test_all_event_types_valid(self):
        for et in EventType:
            event = AIEvent(event_type=et, source="test")
            d = event.to_dict()
            assert d["event_type"] == et.value

    def test_timestamp_set_automatically(self, ai_event):
        assert ai_event.timestamp  # Non-empty
        assert "T" in ai_event.timestamp  # ISO format


# ── Engine Initialization ─────────────────────────────────────────────────────


class TestEngineInit:
    """Tests for TelemetryEngine initialization."""

    def test_default_init(self):
        engine = TelemetryEngine()
        assert engine.batch_size == 100
        assert engine.flush_interval == 5.0
        assert engine.fallback_to_file is True
        assert engine._running is False
        assert engine._ch_available is False
        assert engine._client is None

    def test_custom_init(self):
        engine = TelemetryEngine(
            clickhouse_host="myhost",
            clickhouse_port=9001,
            database="mydb",
            batch_size=50,
            flush_interval_seconds=10.0,
            fallback_to_file=False,
        )
        assert engine.ch_host == "myhost"
        assert engine.ch_port == 9001
        assert engine.database == "mydb"
        assert engine.batch_size == 50
        assert engine.flush_interval == 10.0
        assert engine.fallback_to_file is False

    def test_env_override_host(self, monkeypatch):
        monkeypatch.setenv("CLICKHOUSE_HOST", "env-host")
        monkeypatch.setenv("CLICKHOUSE_PORT", "9002")
        engine = TelemetryEngine()
        assert engine.ch_host == "env-host"
        assert engine.ch_port == 9002


# ── ClickHouse Init (mocked) ──────────────────────────────────────────────────


class TestClickHouseInit:
    """Tests for _init_clickhouse() with mocked driver."""

    def test_clickhouse_connected_on_start(self, tmp_path):
        mock_client = MagicMock()
        mock_ch_module = MagicMock()
        mock_ch_module.Client.return_value = mock_client

        engine = TelemetryEngine(log_file=str(tmp_path / "events.jsonl"))

        with patch.dict("sys.modules", {"clickhouse_driver": mock_ch_module}):
            engine._init_clickhouse()

        assert engine._ch_available is True
        # Should have created DB and table
        calls = [str(c) for c in mock_client.execute.call_args_list]
        assert any("CREATE DATABASE" in str(c) or "CREATE TABLE" in str(c) for c in calls)

    def test_clickhouse_unavailable_on_import_error(self, tmp_path):
        engine = TelemetryEngine(log_file=str(tmp_path / "events.jsonl"))

        with patch.dict("sys.modules", {"clickhouse_driver": None}):
            with patch("builtins.__import__", side_effect=ImportError("no module")):
                engine._init_clickhouse()
        # ch_available stays False (set in __init__)
        assert engine._ch_available is False

    def test_clickhouse_unavailable_on_connection_error(self, tmp_path):
        mock_ch_module = MagicMock()
        mock_ch_module.Client.side_effect = Exception("Connection refused")

        engine = TelemetryEngine(log_file=str(tmp_path / "events.jsonl"))

        with patch.dict("sys.modules", {"clickhouse_driver": mock_ch_module}):
            engine._init_clickhouse()

        assert engine._ch_available is False


# ── Event Logging ─────────────────────────────────────────────────────────────


class TestEventLogging:
    """Tests for log() and log_many()."""

    def test_log_adds_to_buffer(self, engine_no_ch, ai_event):
        engine_no_ch.log(ai_event)
        assert len(engine_no_ch._buffer) == 1

    def test_log_many_adds_all(self, engine_no_ch, ai_event, guardrail_event):
        engine_no_ch.log_many([ai_event, guardrail_event])
        assert len(engine_no_ch._buffer) == 2

    def test_auto_flush_on_batch_size(self, tmp_path):
        """Buffer should auto-flush when batch_size is reached."""
        log_file = str(tmp_path / "events.jsonl")
        engine = TelemetryEngine(
            batch_size=3,
            fallback_to_file=True,
            log_file=log_file,
        )
        events = [
            AIEvent(event_type=EventType.AI_REQUEST, source="test")
            for _ in range(3)
        ]
        for ev in events:
            engine.log(ev)
        # After 3 events (== batch_size), should have been flushed
        assert len(engine._buffer) == 0
        assert os.path.exists(log_file)
        with open(log_file) as f:
            lines = f.readlines()
        assert len(lines) == 3

    def test_log_many_auto_flush(self, tmp_path):
        log_file = str(tmp_path / "events.jsonl")
        engine = TelemetryEngine(
            batch_size=2,
            fallback_to_file=True,
            log_file=log_file,
        )
        events = [AIEvent(event_type=EventType.GUARDRAIL, source="test")] * 4
        engine.log_many(events)
        assert len(engine._buffer) == 0


# ── File Fallback ─────────────────────────────────────────────────────────────


class TestFileFallback:
    """Tests for file-based event logging when ClickHouse is unavailable."""

    def test_file_fallback_writes_jsonl(self, engine_no_ch, ai_event, tmp_path):
        engine_no_ch.log(ai_event)
        engine_no_ch._flush()

        log_file = engine_no_ch.log_file
        assert os.path.exists(log_file)
        with open(log_file) as f:
            lines = f.readlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["event_type"] == "ai_request"
        assert parsed["source"] == "test"

    def test_file_fallback_multiple_events(self, engine_no_ch, ai_event, guardrail_event):
        engine_no_ch.log(ai_event)
        engine_no_ch.log(guardrail_event)
        engine_no_ch._flush()

        with open(engine_no_ch.log_file) as f:
            lines = f.readlines()
        assert len(lines) == 2

    def test_no_file_when_fallback_disabled(self, tmp_path, ai_event):
        log_file = str(tmp_path / "noop.jsonl")
        engine = TelemetryEngine(fallback_to_file=False, log_file=log_file)
        engine.log(ai_event)
        engine._flush()
        assert not os.path.exists(log_file)

    def test_flush_clears_buffer(self, engine_no_ch, ai_event):
        engine_no_ch.log(ai_event)
        assert len(engine_no_ch._buffer) == 1
        engine_no_ch._flush()
        assert len(engine_no_ch._buffer) == 0

    def test_flush_empty_buffer_is_noop(self, engine_no_ch, tmp_path):
        """Flushing an empty buffer should not create a file."""
        engine_no_ch._flush()
        assert not os.path.exists(engine_no_ch.log_file)


# ── ClickHouse Flush (mocked) ─────────────────────────────────────────────────


class TestClickHouseFlush:
    """Tests for flushing events to ClickHouse."""

    def test_flush_to_clickhouse_calls_execute(self, tmp_path, ai_event):
        mock_client = MagicMock()
        log_file = str(tmp_path / "events.jsonl")
        engine = TelemetryEngine(fallback_to_file=True, log_file=log_file)
        engine._ch_available = True
        engine._client = mock_client

        engine.log(ai_event)
        engine._flush()

        mock_client.execute.assert_called_once()
        call_args = mock_client.execute.call_args
        assert "INSERT INTO ai_events VALUES" in call_args[0][0]
        rows = call_args[0][1]
        assert len(rows) == 1

    def test_clickhouse_flush_failure_falls_back_to_file(self, tmp_path, ai_event):
        mock_client = MagicMock()
        mock_client.execute.side_effect = Exception("Insert failed")
        log_file = str(tmp_path / "events.jsonl")

        engine = TelemetryEngine(fallback_to_file=True, log_file=log_file)
        engine._ch_available = True
        engine._client = mock_client

        engine.log(ai_event)
        engine._flush()

        # Should have fallen back to file
        assert os.path.exists(log_file)
        with open(log_file) as f:
            lines = f.readlines()
        assert len(lines) == 1


# ── Analytics Queries ─────────────────────────────────────────────────────────


class TestAnalyticsQueries:
    """Tests for pre-built analytics queries."""

    def test_all_8_queries_exist(self):
        # Original 8 core queries must always be present; directive may add more
        required = {
            "events_per_hour", "risk_distribution", "top_models",
            "provider_breakdown", "guardrail_violations", "redteam_success_rate",
            "daily_cost", "policy_compliance",
        }
        assert required.issubset(set(ANALYTICS_QUERIES.keys())), (
            f"Missing required queries: {required - set(ANALYTICS_QUERIES.keys())}"
        )

    def test_query_sql_not_empty(self):
        for name, sql in ANALYTICS_QUERIES.items():
            assert sql.strip(), f"Query '{name}' is empty"
            assert "SELECT" in sql.upper()
            # Queries may read from materialized views or ai_events directly
            assert any(kw in sql.upper() for kw in ("FROM AI_EVENTS", "FROM AI_", "FROM CSPM_")), (
                f"Query '{name}' does not appear to read from an Aegis table"
            )

    def test_query_returns_empty_without_clickhouse(self, engine_no_ch):
        result = engine_no_ch.query("events_per_hour")
        assert result == []

    def test_query_unknown_returns_empty(self, engine_no_ch):
        result = engine_no_ch.query("nonexistent_query")
        assert result == []

    def test_query_with_mock_clickhouse(self, tmp_path):
        mock_client = MagicMock()
        mock_client.execute.return_value = [("2026-04-01 10:00:00", 42)]
        engine = TelemetryEngine(log_file=str(tmp_path / "test.jsonl"))
        engine._ch_available = True
        engine._client = mock_client

        result = engine.query("events_per_hour")
        assert len(result) == 1
        assert result[0]["row"] == ["2026-04-01 10:00:00", 42]

    def test_query_raw_with_mock(self, tmp_path):
        mock_client = MagicMock()
        mock_client.execute.return_value = [(1, 2, 3)]
        engine = TelemetryEngine(log_file=str(tmp_path / "test.jsonl"))
        engine._ch_available = True
        engine._client = mock_client

        result = engine.query_raw("SELECT 1, 2, 3")
        assert result == [(1, 2, 3)]

    def test_query_raw_without_clickhouse(self, engine_no_ch):
        result = engine_no_ch.query_raw("SELECT 1")
        assert result == []


# ── Engine Stats ──────────────────────────────────────────────────────────────


class TestGetStats:
    """Tests for get_stats()."""

    def test_stats_fields(self, engine_no_ch):
        stats = engine_no_ch.get_stats()
        assert "buffer_size" in stats
        assert "clickhouse_available" in stats
        assert "clickhouse_host" in stats
        assert "batch_size" in stats
        assert "flush_interval" in stats
        assert "running" in stats

    def test_stats_buffer_size(self, engine_no_ch, ai_event):
        assert engine_no_ch.get_stats()["buffer_size"] == 0
        engine_no_ch.log(ai_event)
        assert engine_no_ch.get_stats()["buffer_size"] == 1

    def test_stats_not_running_before_start(self, engine_no_ch):
        assert engine_no_ch.get_stats()["running"] is False


# ── Engine Lifecycle ──────────────────────────────────────────────────────────


class TestEngineLifecycle:
    """Tests for start/stop lifecycle."""

    def test_start_sets_running(self, tmp_path):
        log_file = str(tmp_path / "lifecycle.jsonl")
        engine = TelemetryEngine(
            flush_interval_seconds=60.0,
            fallback_to_file=False,
            log_file=log_file,
        )
        engine.start()
        assert engine._running is True
        assert engine._flush_thread is not None
        assert engine._flush_thread.is_alive()
        engine.stop()

    def test_stop_sets_not_running(self, tmp_path):
        log_file = str(tmp_path / "lifecycle.jsonl")
        engine = TelemetryEngine(
            flush_interval_seconds=60.0,
            fallback_to_file=False,
            log_file=log_file,
        )
        engine.start()
        engine.stop()
        assert engine._running is False

    def test_stop_flushes_remaining_events(self, tmp_path):
        log_file = str(tmp_path / "lifecycle.jsonl")
        engine = TelemetryEngine(
            batch_size=1000,
            flush_interval_seconds=60.0,
            fallback_to_file=True,
            log_file=log_file,
        )
        engine.start()
        engine.log(AIEvent(event_type=EventType.SYSTEM, source="lifecycle-test"))
        assert len(engine._buffer) == 1
        engine.stop()
        # Buffer should be cleared by stop's flush
        assert len(engine._buffer) == 0

    def test_thread_is_daemon(self, tmp_path):
        log_file = str(tmp_path / "lifecycle.jsonl")
        engine = TelemetryEngine(
            flush_interval_seconds=60.0,
            fallback_to_file=False,
            log_file=log_file,
        )
        engine.start()
        assert engine._flush_thread.daemon is True
        engine.stop()


# ── CLICKHOUSE_CREATE_TABLE Schema ────────────────────────────────────────────


class TestClickHouseSchema:
    """Verify the CREATE TABLE SQL is well-formed."""

    def test_create_table_sql_present(self):
        assert CLICKHOUSE_CREATE_TABLE
        assert "CREATE TABLE IF NOT EXISTS ai_events" in CLICKHOUSE_CREATE_TABLE

    def test_required_columns(self):
        required_cols = [
            "event_type", "source", "severity", "data",
            "user_id", "session_id", "model", "provider",
            "input_tokens", "output_tokens", "latency_ms",
            "cost_usd", "risk_score", "timestamp",
        ]
        for col in required_cols:
            assert col in CLICKHOUSE_CREATE_TABLE, f"Column '{col}' missing from schema"

    def test_ttl_and_engine_present(self):
        assert "MergeTree" in CLICKHOUSE_CREATE_TABLE
        assert "TTL" in CLICKHOUSE_CREATE_TABLE

    def test_partition_by_date(self):
        assert "PARTITION BY" in CLICKHOUSE_CREATE_TABLE
