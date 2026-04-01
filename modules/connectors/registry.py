"""
Connector Registry — singleton that manages provider instances.

Usage:
    registry = ConnectorRegistry()
    registry.register_from_env()       # Auto-detect from environment
    llm = registry.get("openai")       # Get a specific provider
    llm = registry.get_default()       # Get the configured default
"""

import os
import logging
from typing import Dict, Optional

from modules.connectors.base import LLMConnector, ProviderType
from modules.connectors.openai_connector import OpenAIConnector
from modules.connectors.anthropic_connector import AnthropicConnector

logger = logging.getLogger("aegis.connectors.registry")


class ConnectorRegistry:
    """Central registry for all LLM provider connectors."""

    def __init__(self):
        self._connectors: Dict[str, LLMConnector] = {}
        self._default: Optional[str] = None

    def register(self, name: str, connector: LLMConnector, *, default: bool = False):
        self._connectors[name] = connector
        if default or self._default is None:
            self._default = name
        logger.info("Registered LLM connector: %s (provider=%s)", name, connector.provider.value)

    def get(self, name: str) -> Optional[LLMConnector]:
        return self._connectors.get(name)

    def get_default(self) -> Optional[LLMConnector]:
        if self._default:
            return self._connectors.get(self._default)
        return None

    def list_providers(self) -> Dict[str, str]:
        return {name: c.provider.value for name, c in self._connectors.items()}

    def register_from_env(self):
        """Auto-detect available providers from environment variables."""

        # OpenAI / OpenAI-compatible (Ollama, vLLM, Groq, LM Studio)
        if os.getenv("OPENAI_API_KEY") or os.getenv("OPENAI_BASE_URL"):
            base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
            model = os.getenv("OPENAI_MODEL", "gpt-4o")
            api_key = os.getenv("OPENAI_API_KEY", "")

            # Detect provider type from base URL
            ptype = ProviderType.OPENAI
            if "localhost" in base_url or "127.0.0.1" in base_url:
                if "11434" in base_url:
                    ptype = ProviderType.OLLAMA
                elif "1234" in base_url:
                    ptype = ProviderType.LM_STUDIO
                else:
                    ptype = ProviderType.VLLM

            connector = OpenAIConnector(
                api_key=api_key,
                base_url=base_url,
                default_model=model,
                provider=ptype,
            )
            self.register("openai", connector, default=True)

        # Anthropic
        if os.getenv("ANTHROPIC_API_KEY"):
            connector = AnthropicConnector(
                api_key=os.getenv("ANTHROPIC_API_KEY", ""),
                default_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            )
            is_default = not self._default  # Default only if nothing else registered
            self.register("anthropic", connector, default=is_default)

        if not self._connectors:
            logger.warning("No LLM connectors detected — set OPENAI_API_KEY or ANTHROPIC_API_KEY")
