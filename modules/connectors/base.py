"""
LLM Connector base classes and shared types.

Every provider connector inherits from LLMConnector and implements query().
All calls are automatically instrumented for telemetry.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import logging
import time

logger = logging.getLogger("aegis.connectors")


class ProviderType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    GOOGLE_VERTEX = "google_vertex"
    OLLAMA = "ollama"
    VLLM = "vllm"
    LM_STUDIO = "lm_studio"
    CUSTOM = "custom"


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str
    model: str
    provider: ProviderType
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cost_usd: float = 0.0
    finish_reason: str = "stop"
    raw_response: Optional[Dict[str, Any]] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "content": self.content,
            "model": self.model,
            "provider": self.provider.value,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "latency_ms": self.latency_ms,
            "cost_usd": self.cost_usd,
            "finish_reason": self.finish_reason,
            "timestamp": self.timestamp,
        }


# Approximate cost per 1K tokens (input/output) — updated March 2026
COST_TABLE: Dict[str, tuple] = {
    "gpt-4": (0.03, 0.06),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "claude-sonnet-4-6": (0.003, 0.015),
    "claude-opus-4-6": (0.015, 0.075),
    "claude-haiku-4-5": (0.0008, 0.004),
}


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost based on known pricing tables."""
    for key, (inp, out) in COST_TABLE.items():
        if key in model.lower():
            return (input_tokens / 1000 * inp) + (output_tokens / 1000 * out)
    return 0.0  # Unknown model — cost tracking requires config


class LLMConnector(ABC):
    """Abstract base class for all LLM provider connectors."""

    provider: ProviderType = ProviderType.CUSTOM
    default_model: str = ""

    @abstractmethod
    def query(
        self,
        prompt: str,
        *,
        model: Optional[str] = None,
        system: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        messages: Optional[List[Dict[str, str]]] = None,
    ) -> LLMResponse:
        """Send a prompt (or message list) and return a standardized response."""
        ...

    def is_available(self) -> bool:
        """Return True if this connector's credentials/endpoints are reachable."""
        return True

    def _timed_query(self, fn, *args, **kwargs) -> LLMResponse:
        """Wrapper that measures latency and adds cost estimation."""
        t0 = time.perf_counter()
        resp: LLMResponse = fn(*args, **kwargs)
        resp.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        resp.cost_usd = estimate_cost(resp.model, resp.input_tokens, resp.output_tokens)
        return resp
