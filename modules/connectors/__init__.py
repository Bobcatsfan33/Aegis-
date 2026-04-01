"""
Multi-Provider LLM Connectors — v3.0.0

Unified abstraction layer for LLM providers: OpenAI, Anthropic, local models
(Ollama, vLLM, LM Studio), Azure OpenAI, AWS Bedrock, and Google Vertex AI.
Every call is instrumented with latency, token counts, and cost estimation,
then forwarded to the telemetry pipeline.

Replaces the existing single openai connector in config.py with a provider-
agnostic interface that the red team and guardrails engines consume.
"""

from modules.connectors.base import LLMConnector, LLMResponse, ProviderType
from modules.connectors.registry import ConnectorRegistry

__all__ = ["LLMConnector", "LLMResponse", "ProviderType", "ConnectorRegistry"]
