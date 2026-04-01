"""
AI Asset Discovery Engine — v3.0.0

Enumerates AI/ML assets across the environment: LLM API keys in env/secrets,
model endpoints, prompt stores, vector databases, AI service registrations,
and internal model-serving infrastructure.

NIST 800-53 controls: CM-8 (Information System Component Inventory),
PM-5 (System Inventory), RA-5 (Vulnerability Monitoring & Scanning).
"""

from modules.discovery.engine import DiscoveryEngine, AIAsset, AssetType

__all__ = ["DiscoveryEngine", "AIAsset", "AssetType"]
