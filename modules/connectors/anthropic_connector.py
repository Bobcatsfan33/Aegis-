"""
Anthropic Claude connector.

Supports Claude Opus 4, Sonnet 4, Haiku 3.5+ via the Anthropic Python SDK.
"""

import logging
from typing import Dict, List, Optional

from modules.connectors.base import LLMConnector, LLMResponse, ProviderType

logger = logging.getLogger("aegis.connectors.anthropic")

try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore


class AnthropicConnector(LLMConnector):
    """Anthropic Claude LLM connector."""

    provider = ProviderType.ANTHROPIC

    def __init__(
        self,
        api_key: str,
        default_model: str = "claude-sonnet-4-6",
    ):
        if anthropic is None:
            raise ImportError("anthropic package required: pip install anthropic")

        self.default_model = default_model
        self._client = anthropic.Anthropic(api_key=api_key)
        logger.info("Anthropic connector initialized (model=%s)", default_model)

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
        model = model or self.default_model
        if messages is None:
            messages = [{"role": "user", "content": prompt}]

        def _call():
            kwargs = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if system:
                kwargs["system"] = system

            resp = self._client.messages.create(**kwargs)
            content = resp.content[0].text if resp.content else ""
            return LLMResponse(
                content=content,
                model=model,
                provider=self.provider,
                input_tokens=resp.usage.input_tokens if resp.usage else 0,
                output_tokens=resp.usage.output_tokens if resp.usage else 0,
                finish_reason=resp.stop_reason or "end_turn",
                raw_response=resp.model_dump() if hasattr(resp, "model_dump") else None,
            )

        return self._timed_query(_call)

    def is_available(self) -> bool:
        try:
            # Lightweight check — list models endpoint
            self._client.models.list(limit=1)
            return True
        except Exception:
            return False
