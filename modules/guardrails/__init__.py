"""
Runtime Guardrails Engine — v3.0.0

Inline enforcement layer that inspects LLM prompts and responses in real time.
Blocks or flags: PII leakage (SSN, credit cards, emails), secrets exposure
(API keys, tokens, passwords), prompt injection attempts, toxic/harmful content,
and policy-violating outputs.  Operates as middleware in the request path.

NIST 800-53: SC-7 (Boundary Protection), SI-10 (Information Input Validation),
AC-4 (Information Flow Enforcement).
"""

from modules.guardrails.engine import GuardrailsEngine, GuardrailVerdict, ViolationType

__all__ = ["GuardrailsEngine", "GuardrailVerdict", "ViolationType"]
