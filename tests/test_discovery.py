"""
Unit tests for AegisAI Discovery Engine.

Tests the AI asset discovery scanner: environment variable detection,
network endpoint probing, endpoint URL scanning, and summary generation.
"""

import os
import socket
from unittest.mock import patch, MagicMock

import pytest

# Ensure project root on path (conftest handles this, but be explicit)
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.discovery.engine import (
    DiscoveryEngine,
    AIAsset,
    AssetType,
    API_KEY_PATTERNS,
    AI_SERVICE_PORTS,
)


# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def clean_env(monkeypatch):
    """Remove all AI-related env vars so tests start from a known state."""
    ai_vars = [
        "OPENAI_API_KEY", "OPENAI_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_KEY",
        "CLAUDE_API_KEY", "GOOGLE_API_KEY", "VERTEX_AI_KEY", "GEMINI_API_KEY",
        "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_KEY", "COHERE_API_KEY",
        "MISTRAL_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY",
        "FIREWORKS_API_KEY", "REPLICATE_API_TOKEN", "HUGGING_FACE_HUB_TOKEN",
        "HF_TOKEN", "PINECONE_API_KEY", "WEAVIATE_API_KEY", "QDRANT_API_KEY",
        "LANGCHAIN_API_KEY", "LANGSMITH_API_KEY",
        "OPENAI_BASE_URL", "AZURE_OPENAI_ENDPOINT", "OLLAMA_HOST",
        "VLLM_URL", "PINECONE_ENVIRONMENT", "WEAVIATE_URL", "QDRANT_URL",
        "CHROMA_HOST", "MLFLOW_TRACKING_URI", "LANGCHAIN_TRACING_V2",
    ]
    for var in ai_vars:
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


@pytest.fixture
def engine_no_network():
    """Engine with network scanning disabled (pure env scanning)."""
    return DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)


# ── Environment Variable Detection ──────────────────────────────────────


class TestEnvironmentScanning:
    """Tests for _scan_environment() — detecting AI API keys in env vars."""

    def test_detects_openai_key(self, clean_env):
        clean_env.setenv("OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        openai_assets = [a for a in assets if a.provider == "openai"]
        assert len(openai_assets) >= 1
        asset = openai_assets[0]
        assert asset.asset_type == AssetType.LLM_API_KEY
        assert asset.identifier == "OPENAI_API_KEY"
        assert asset.location == "environment_variable"
        assert asset.risk_level == "high"
        assert "CM-8" in asset.nist_controls

    def test_detects_anthropic_key(self, clean_env):
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        anthropic_assets = [a for a in assets if a.provider == "anthropic"]
        assert len(anthropic_assets) >= 1
        assert anthropic_assets[0].asset_type == AssetType.LLM_API_KEY
        assert anthropic_assets[0].risk_level == "high"

    def test_detects_google_key(self, clean_env):
        clean_env.setenv("GOOGLE_API_KEY", "AIzaSomeFakeKeyValue12345")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        google_assets = [a for a in assets if a.provider == "google"]
        assert len(google_assets) >= 1

    def test_detects_vector_db_key(self, clean_env):
        clean_env.setenv("PINECONE_API_KEY", "pc-abcdef1234567890")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        vdb_assets = [a for a in assets if a.provider == "vector_db"]
        assert len(vdb_assets) >= 1
        assert vdb_assets[0].asset_type == AssetType.VECTOR_DB

    def test_detects_third_party_llm_keys(self, clean_env):
        clean_env.setenv("GROQ_API_KEY", "gsk_testkey12345678901234567890")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        third_party = [a for a in assets if a.provider == "third_party_llm"]
        assert len(third_party) >= 1
        assert third_party[0].risk_level == "medium"

    def test_no_false_positives_on_unrelated_vars(self, clean_env):
        clean_env.setenv("HOME", "/home/user")
        clean_env.setenv("PATH", "/usr/bin:/usr/local/bin")
        clean_env.setenv("DATABASE_URL", "postgres://localhost/mydb")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        # Only env-endpoint assets should appear (if DATABASE_URL matches), not API keys
        api_key_assets = [a for a in assets if a.asset_type == AssetType.LLM_API_KEY]
        assert len(api_key_assets) == 0

    def test_masks_secret_values(self, clean_env):
        key_val = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno"
        clean_env.setenv("OPENAI_API_KEY", key_val)
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        openai_assets = [a for a in assets if a.provider == "openai"]
        assert len(openai_assets) >= 1
        masked = openai_assets[0].details.get("masked_value", "")
        # Must NOT contain the full key
        assert masked != key_val
        assert "..." in masked

    def test_multiple_keys_detected(self, clean_env):
        clean_env.setenv("OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno")
        clean_env.setenv("ANTHROPIC_API_KEY", "sk-ant-abcdefghijklmnopqrstuvwxyz1234567890")
        clean_env.setenv("PINECONE_API_KEY", "pc-12345678901234567890")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        providers = {a.provider for a in assets if a.asset_type in (AssetType.LLM_API_KEY, AssetType.VECTOR_DB)}
        assert "openai" in providers
        assert "anthropic" in providers
        assert "vector_db" in providers

    def test_mitre_atlas_mapping(self, clean_env):
        clean_env.setenv("OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        openai_assets = [a for a in assets if a.provider == "openai"]
        assert len(openai_assets) >= 1
        assert "AML.T0024" in openai_assets[0].mitre_atlas


# ── Environment Endpoint Detection ──────────────────────────────────────


class TestEnvEndpointScanning:
    """Tests for _scan_env_endpoints() — detecting AI endpoint URLs in env."""

    def test_detects_openai_base_url(self, clean_env):
        clean_env.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        endpoint_assets = [a for a in assets if a.identifier == "OPENAI_BASE_URL"]
        assert len(endpoint_assets) == 1
        assert endpoint_assets[0].asset_type == AssetType.LLM_ENDPOINT
        assert endpoint_assets[0].exposure == "public"

    def test_detects_local_ollama_host(self, clean_env):
        clean_env.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        ollama = [a for a in assets if a.identifier == "OLLAMA_HOST"]
        assert len(ollama) == 1
        assert ollama[0].exposure == "internal"
        assert ollama[0].risk_level == "low"

    def test_detects_vector_db_url(self, clean_env):
        clean_env.setenv("QDRANT_URL", "https://qdrant.example.com:6333")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        qdrant = [a for a in assets if a.identifier == "QDRANT_URL"]
        assert len(qdrant) == 1
        assert qdrant[0].asset_type == AssetType.VECTOR_DB

    def test_detects_mlflow_tracking(self, clean_env):
        clean_env.setenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        mlflow = [a for a in assets if a.identifier == "MLFLOW_TRACKING_URI"]
        assert len(mlflow) == 1
        assert mlflow[0].asset_type == AssetType.MODEL_REGISTRY

    def test_public_vs_internal_exposure(self, clean_env):
        clean_env.setenv("WEAVIATE_URL", "https://weaviate-cloud.example.com")
        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        weaviate = [a for a in assets if a.identifier == "WEAVIATE_URL"]
        assert len(weaviate) == 1
        assert weaviate[0].exposure == "public"
        assert weaviate[0].risk_level == "medium"


# ── Network Endpoint Probing ────────────────────────────────────────────


class TestNetworkScanning:
    """Tests for _scan_endpoints() — probing known AI service ports."""

    def test_detects_open_port(self, clean_env):
        """Mock a successful socket connection to simulate an open Ollama port."""
        engine = DiscoveryEngine(scan_env=False, scan_network=False, scan_localhost=True)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0  # Port open

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            assets = engine.scan()

        # Should find assets for all AI_SERVICE_PORTS (all return open)
        assert len(assets) >= 1
        endpoints = [a for a in assets if a.location == "network"]
        assert len(endpoints) > 0

    def test_closed_ports_yield_no_assets(self, clean_env):
        """All ports closed — no network assets discovered."""
        engine = DiscoveryEngine(scan_env=False, scan_network=False, scan_localhost=True)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Port closed

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            assets = engine.scan()

        network_assets = [a for a in assets if a.location == "network"]
        assert len(network_assets) == 0

    def test_socket_error_handled_gracefully(self, clean_env):
        """Socket errors should not crash the scan."""
        engine = DiscoveryEngine(scan_env=False, scan_network=False, scan_localhost=True)
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.error("Connection refused")

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            # Should not raise
            assets = engine.scan()

        assert isinstance(assets, list)

    def test_public_exposure_for_remote_hosts(self, clean_env):
        """Assets on non-localhost hosts should be marked as public exposure."""
        engine = DiscoveryEngine(
            scan_env=False, scan_network=True, scan_localhost=False,
            network_targets=["10.0.0.5"],
        )
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            assets = engine.scan()

        public_assets = [a for a in assets if a.exposure == "public"]
        assert len(public_assets) > 0
        # Public assets should be critical risk
        for a in public_assets:
            assert a.risk_level == "critical"

    def test_localhost_exposure_internal(self, clean_env):
        """Assets on localhost should be marked as internal exposure."""
        engine = DiscoveryEngine(scan_env=False, scan_network=False, scan_localhost=True)
        mock_sock = MagicMock()
        # Only open port 11434 (Ollama)
        def connect_side_effect(addr):
            return 0 if addr[1] == 11434 else 1
        mock_sock.connect_ex.side_effect = connect_side_effect

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            assets = engine.scan()

        ollama_assets = [a for a in assets if a.provider == "ollama" and a.location == "network"]
        assert len(ollama_assets) == 1
        assert ollama_assets[0].exposure == "internal"
        assert ollama_assets[0].risk_level == "medium"


# ── Engine Configuration ────────────────────────────────────────────────


class TestEngineConfiguration:
    """Tests for DiscoveryEngine init options."""

    def test_default_config(self):
        engine = DiscoveryEngine()
        assert engine.scan_env is True
        assert engine.scan_network is True
        assert engine.scan_localhost is True
        assert engine.network_targets == ["127.0.0.1"]

    def test_custom_targets(self):
        engine = DiscoveryEngine(network_targets=["192.168.1.100", "10.0.0.1"])
        assert "192.168.1.100" in engine.network_targets
        assert "10.0.0.1" in engine.network_targets

    def test_disable_all_scanning(self, clean_env):
        engine = DiscoveryEngine(scan_env=False, scan_network=False, scan_localhost=False)
        assets = engine.scan()
        assert len(assets) == 0


# ── AIAsset Data Model ──────────────────────────────────────────────────


class TestAIAssetModel:
    """Tests for the AIAsset dataclass."""

    def test_to_dict(self):
        asset = AIAsset(
            asset_type=AssetType.LLM_API_KEY,
            identifier="OPENAI_API_KEY",
            provider="openai",
            location="environment_variable",
            exposure="internal",
            risk_level="high",
        )
        d = asset.to_dict()
        assert d["asset_type"] == "llm_api_key"
        assert d["identifier"] == "OPENAI_API_KEY"
        assert d["provider"] == "openai"
        assert d["risk_level"] == "high"
        assert "CM-8" in d["nist_controls"]
        assert "timestamp" in d

    def test_default_nist_controls(self):
        asset = AIAsset(
            asset_type=AssetType.LLM_ENDPOINT,
            identifier="localhost:11434",
            provider="ollama",
            location="network",
            exposure="internal",
            risk_level="medium",
        )
        assert "CM-8" in asset.nist_controls
        assert "PM-5" in asset.nist_controls


# ── Summary Generation ──────────────────────────────────────────────────


class TestSummaryGeneration:
    """Tests for DiscoveryEngine.summary()."""

    def test_summary_empty(self):
        engine = DiscoveryEngine()
        summary = engine.summary([])
        assert summary["total_assets"] == 0
        assert summary["by_type"] == {}
        assert summary["nist_controls_covered"] == ["CM-8", "PM-5", "RA-5"]

    def test_summary_counts(self):
        engine = DiscoveryEngine()
        assets = [
            AIAsset(AssetType.LLM_API_KEY, "key1", "openai", "env", "internal", "high"),
            AIAsset(AssetType.LLM_API_KEY, "key2", "anthropic", "env", "internal", "high"),
            AIAsset(AssetType.VECTOR_DB, "qdrant", "qdrant", "network", "internal", "medium"),
        ]
        summary = engine.summary(assets)
        assert summary["total_assets"] == 3
        assert summary["by_type"]["llm_api_key"] == 2
        assert summary["by_type"]["vector_database"] == 1
        assert summary["by_risk_level"]["high"] == 2
        assert summary["by_risk_level"]["medium"] == 1
        assert summary["by_provider"]["openai"] == 1
        assert summary["by_provider"]["anthropic"] == 1
        assert summary["by_provider"]["qdrant"] == 1

    def test_summary_has_timestamp(self):
        engine = DiscoveryEngine()
        summary = engine.summary([])
        assert "timestamp" in summary


# ── Integration-style: Full Scan with Mixed Sources ─────────────────────


class TestFullScan:
    """Integration tests combining env + network scanning."""

    def test_combined_env_and_network_scan(self, clean_env):
        clean_env.setenv("OPENAI_API_KEY", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmno")
        clean_env.setenv("OLLAMA_HOST", "http://127.0.0.1:11434")

        engine = DiscoveryEngine(scan_env=True, scan_network=False, scan_localhost=True)
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # All ports closed

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            assets = engine.scan()

        # Should have the API key + the OLLAMA_HOST endpoint var
        providers = {a.provider for a in assets}
        assert "openai" in providers
        assert "ollama" in providers

    def test_dedup_targets(self, clean_env):
        """Ensure 127.0.0.1 isn't scanned twice when both localhost and network are on."""
        engine = DiscoveryEngine(
            scan_env=False, scan_network=True, scan_localhost=True,
            network_targets=["127.0.0.1"],
        )
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1

        with patch("modules.discovery.engine.socket.socket", return_value=mock_sock):
            engine.scan()

        # Each port should only be probed once for 127.0.0.1
        # Total calls = len(AI_SERVICE_PORTS) (one per port, one host)
        expected_calls = len(AI_SERVICE_PORTS)
        assert mock_sock.connect_ex.call_count == expected_calls
