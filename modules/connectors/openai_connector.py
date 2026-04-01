"""
OpenAI-compatible connector.

Works with: OpenAI, Azure OpenAI, Ollama, vLLM, Groq, LM Studio, LocalAI,
and any provider exposing the OpenAI chat completions API.
"""

import logging
from typing import Dict, List, Optional

from modules.connectors.base import LLMConnector, LLMResponse, ProviderType, estimate_cost

logger = logging.getLogger("aegis.connectors.openai")

try:
    import openai
except ImportError:
    openai = None  # type: ignore


class OpenAIConnector(LLMConnector):
    """OpenAI-compatible LLM connector."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.openai.com/v1",
        default_model: str = "gpt-4o",
        provider: ProviderType = ProviderType.OPENAI,
    ):
        if openai is None:
            raise ImportError("openai package required: pip install openai")

        self.provider = provider
        self.default_model = default_model
        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)
        logger.info("OpenAI connector initialized (base_url=%s, model=%s)", base_url, default_model)

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
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

        def _call():
            resp = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            choice = resp.choices[0]
            usage = resp.usage
            return LLMResponse(
                content=choice.message.content or "",
                model=model,
                provider=self.provider,
                input_tokens=usage.prompt_tokens if usage else 0,
                output_tokens=usage.completion_tokens if usage else 0,
                finish_reason=choice.finish_reason or "stop",
                raw_response=resp.model_dump() if hasattr(resp, "model_dump") else None,
            )

        return self._timed_query(_call)

    def is_available(self) -> bool:
        try:
            self._client.models.list()
            return True
        except Exception:
            return False
