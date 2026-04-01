"""
AI Asset Discovery Engine.

Scans the environment to build a comprehensive inventory of AI/ML assets:
  - LLM API keys and tokens (environment, secrets backends, config files)
  - Model-serving endpoints (OpenAI, Anthropic, Ollama, vLLM, Bedrock, etc.)
  - Vector databases (Pinecone, Weaviate, Qdrant, Chroma, Milvus)
  - Prompt stores and template repositories
  - AI agent frameworks (LangChain, CrewAI, AutoGen, OpenClaw)
  - GPU/compute resources (if K8s or cloud provider scanning enabled)
  - Model registries (MLflow, SageMaker, Vertex AI Model Registry)

Each discovered asset is classified by type, risk exposure, and compliance
status (CM-8, PM-5), then forwarded to the policy engine for risk scoring.
"""

import logging
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aegis.discovery")


class AssetType(str, Enum):
    LLM_API_KEY = "llm_api_key"
    LLM_ENDPOINT = "llm_endpoint"
    VECTOR_DB = "vector_database"
    MODEL_REGISTRY = "model_registry"
    PROMPT_STORE = "prompt_store"
    AI_AGENT_FRAMEWORK = "ai_agent_framework"
    GPU_RESOURCE = "gpu_resource"
    EMBEDDING_SERVICE = "embedding_service"
    AI_GATEWAY = "ai_gateway"
    FINE_TUNE_JOB = "fine_tune_job"
    TRAINING_DATA = "training_data_store"


@dataclass
class AIAsset:
    """A discovered AI/ML asset in the environment."""
    asset_type: AssetType
    identifier: str             # Key name, URL, service name
    provider: str               # "openai", "anthropic", "aws", "local", etc.
    location: str               # "env", "secrets_manager", "config_file", "network"
    exposure: str               # "internal", "public", "unknown"
    risk_level: str             # "critical", "high", "medium", "low", "info"
    details: Dict[str, Any] = field(default_factory=dict)
    nist_controls: List[str] = field(default_factory=lambda: ["CM-8", "PM-5"])
    mitre_atlas: List[str] = field(default_factory=list)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "asset_type": self.asset_type.value,
            "identifier": self.identifier,
            "provider": self.provider,
            "location": self.location,
            "exposure": self.exposure,
            "risk_level": self.risk_level,
            "details": self.details,
            "nist_controls": self.nist_controls,
            "mitre_atlas": self.mitre_atlas,
            "timestamp": self.timestamp,
        }


# ── Pattern matchers for API keys in environment ──────────────────────

API_KEY_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": re.compile(r"^(OPENAI_API_KEY|OPENAI_KEY)$", re.I),
        "provider": "openai",
        "value_regex": re.compile(r"^sk-[a-zA-Z0-9]{20,}$"),
        "risk": "high",
    },
    {
        "pattern": re.compile(r"^(ANTHROPIC_API_KEY|ANTHROPIC_KEY|CLAUDE_API_KEY)$", re.I),
        "provider": "anthropic",
        "value_regex": re.compile(r"^sk-ant-[a-zA-Z0-9]{20,}$"),
        "risk": "high",
    },
    {
        "pattern": re.compile(r"^(GOOGLE_API_KEY|VERTEX_AI_KEY|GEMINI_API_KEY)$", re.I),
        "provider": "google",
        "value_regex": None,
        "risk": "high",
    },
    {
        "pattern": re.compile(r"^(AZURE_OPENAI_API_KEY|AZURE_OPENAI_KEY)$", re.I),
        "provider": "azure_openai",
        "value_regex": None,
        "risk": "high",
    },
    {
        "pattern": re.compile(r"^(COHERE_API_KEY|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|FIREWORKS_API_KEY|REPLICATE_API_TOKEN|HUGGING_FACE_HUB_TOKEN|HF_TOKEN)$", re.I),
        "provider": "third_party_llm",
        "value_regex": None,
        "risk": "medium",
    },
    {
        "pattern": re.compile(r"^(PINECONE_API_KEY|WEAVIATE_API_KEY|QDRANT_API_KEY)$", re.I),
        "provider": "vector_db",
        "value_regex": None,
        "risk": "medium",
    },
    {
        "pattern": re.compile(r"^(LANGCHAIN_API_KEY|LANGSMITH_API_KEY)$", re.I),
        "provider": "langchain",
        "value_regex": None,
        "risk": "medium",
    },
]

# Well-known AI service ports to probe on localhost/network
AI_SERVICE_PORTS: List[Dict[str, Any]] = [
    {"port": 11434, "service": "Ollama",       "provider": "ollama",   "path": "/api/tags"},
    {"port": 8080,  "service": "vLLM",         "provider": "vllm",     "path": "/health"},
    {"port": 1234,  "service": "LM Studio",    "provider": "lm_studio","path": "/v1/models"},
    {"port": 5000,  "service": "MLflow",        "provider": "mlflow",   "path": "/api/2.0/mlflow/experiments/list"},
    {"port": 6333,  "service": "Qdrant",        "provider": "qdrant",   "path": "/collections"},
    {"port": 8000,  "service": "FastAPI/LLM",   "provider": "custom",   "path": "/docs"},
    {"port": 8888,  "service": "Jupyter",        "provider": "jupyter",  "path": "/api"},
    {"port": 19530, "service": "Milvus",         "provider": "milvus",   "path": "/api/v1/health"},
    {"port": 8090,  "service": "Weaviate",       "provider": "weaviate", "path": "/v1/meta"},
    {"port": 3000,  "service": "Chroma",         "provider": "chroma",   "path": "/api/v1/heartbeat"},
    {"port": 18789, "service": "OpenClaw Gateway","provider": "openclaw", "path": "/health"},
]


class DiscoveryEngine:
    """
    AI Asset Discovery Engine.

    Usage:
        engine = DiscoveryEngine()
        assets = engine.scan()
        # assets: List[AIAsset]
    """

    def __init__(
        self,
        scan_env: bool = True,
        scan_network: bool = True,
        scan_localhost: bool = True,
        network_targets: Optional[List[str]] = None,
        additional_ports: Optional[List[Dict[str, Any]]] = None,
    ):
        self.scan_env = scan_env
        self.scan_network = scan_network
        self.scan_localhost = scan_localhost
        self.network_targets = network_targets or ["127.0.0.1"]
        self.additional_ports = additional_ports or []

    def scan(self) -> List[AIAsset]:
        """Run full discovery scan and return all found AI assets."""
        assets: List[AIAsset] = []

        if self.scan_env:
            assets.extend(self._scan_environment())

        if self.scan_localhost or self.scan_network:
            targets = ["127.0.0.1"] if self.scan_localhost else []
            if self.scan_network:
                targets.extend(self.network_targets)
            # Deduplicate
            targets = list(dict.fromkeys(targets))
            assets.extend(self._scan_endpoints(targets))

        assets.extend(self._scan_env_endpoints())

        logger.info("Discovery complete: %d AI assets found", len(assets))
        return assets

    def _scan_environment(self) -> List[AIAsset]:
        """Scan environment variables for AI API keys and configuration."""
        assets: List[AIAsset] = []

        for key, value in os.environ.items():
            for pattern_def in API_KEY_PATTERNS:
                if pattern_def["pattern"].match(key):
                    # Determine if value looks valid
                    val_regex = pattern_def.get("value_regex")
                    is_valid = val_regex.match(value) if val_regex and value else True
                    # Mask the value — never log secrets
                    masked = f"{value[:8]}...{value[-4:]}" if len(value) > 16 else "***"

                    asset_type = AssetType.VECTOR_DB if pattern_def["provider"] == "vector_db" else AssetType.LLM_API_KEY

                    assets.append(AIAsset(
                        asset_type=asset_type,
                        identifier=key,
                        provider=pattern_def["provider"],
                        location="environment_variable",
                        exposure="internal",
                        risk_level=pattern_def["risk"],
                        details={
                            "masked_value": masked,
                            "appears_valid": is_valid,
                            "note": "API key found in environment — ensure rotation policy in place",
                        },
                        mitre_atlas=["AML.T0024"],  # Exfiltration via Inference API
                    ))
                    logger.info("Discovered %s key: %s", pattern_def["provider"], key)
                    break  # Don't double-match

        return assets

    def _scan_endpoints(self, targets: List[str]) -> List[AIAsset]:
        """Probe known AI service ports on target hosts."""
        assets: List[AIAsset] = []
        all_ports = AI_SERVICE_PORTS + self.additional_ports

        for host in targets:
            for svc in all_ports:
                port = svc["port"]
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1.0)
                    result = sock.connect_ex((host, port))
                    sock.close()

                    if result == 0:
                        exposure = "internal" if host in ("127.0.0.1", "localhost") else "public"
                        assets.append(AIAsset(
                            asset_type=AssetType.LLM_ENDPOINT if "llm" in svc.get("service", "").lower() or svc["provider"] in ("ollama", "vllm", "lm_studio") else AssetType.AI_GATEWAY,
                            identifier=f"{host}:{port}",
                            provider=svc["provider"],
                            location="network",
                            exposure=exposure,
                            risk_level="medium" if exposure == "internal" else "critical",
                            details={
                                "service": svc["service"],
                                "health_path": svc.get("path", "/"),
                                "host": host,
                                "port": port,
                            },
                            mitre_atlas=["AML.T0040"] if exposure == "public" else [],
                        ))
                        logger.info("Discovered %s at %s:%d", svc["service"], host, port)
                except (socket.error, OSError):
                    pass

        return assets

    def _scan_env_endpoints(self) -> List[AIAsset]:
        """Check environment variables that point to AI endpoints/base URLs."""
        assets: List[AIAsset] = []
        endpoint_vars = [
            ("OPENAI_BASE_URL", "openai", AssetType.LLM_ENDPOINT),
            ("AZURE_OPENAI_ENDPOINT", "azure_openai", AssetType.LLM_ENDPOINT),
            ("OLLAMA_HOST", "ollama", AssetType.LLM_ENDPOINT),
            ("VLLM_URL", "vllm", AssetType.LLM_ENDPOINT),
            ("PINECONE_ENVIRONMENT", "pinecone", AssetType.VECTOR_DB),
            ("WEAVIATE_URL", "weaviate", AssetType.VECTOR_DB),
            ("QDRANT_URL", "qdrant", AssetType.VECTOR_DB),
            ("CHROMA_HOST", "chroma", AssetType.VECTOR_DB),
            ("MLFLOW_TRACKING_URI", "mlflow", AssetType.MODEL_REGISTRY),
            ("LANGCHAIN_TRACING_V2", "langchain", AssetType.AI_AGENT_FRAMEWORK),
        ]

        for var, provider, asset_type in endpoint_vars:
            val = os.environ.get(var)
            if val:
                is_public = not any(local in val for local in ("localhost", "127.0.0.1", "10.", "172.", "192.168."))
                assets.append(AIAsset(
                    asset_type=asset_type,
                    identifier=var,
                    provider=provider,
                    location="environment_variable",
                    exposure="public" if is_public else "internal",
                    risk_level="medium" if is_public else "low",
                    details={"value": val, "note": "Endpoint URL configured via environment"},
                ))

        return assets

    def summary(self, assets: List[AIAsset]) -> Dict[str, Any]:
        """Generate a summary report of discovered assets."""
        by_type = {}
        by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_provider = {}

        for a in assets:
            by_type[a.asset_type.value] = by_type.get(a.asset_type.value, 0) + 1
            by_risk[a.risk_level] = by_risk.get(a.risk_level, 0) + 1
            by_provider[a.provider] = by_provider.get(a.provider, 0) + 1

        return {
            "total_assets": len(assets),
            "by_type": by_type,
            "by_risk_level": by_risk,
            "by_provider": by_provider,
            "nist_controls_covered": ["CM-8", "PM-5", "RA-5"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
