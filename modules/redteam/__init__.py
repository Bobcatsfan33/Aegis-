"""
Automated Red Team Engine — v3.0.0

Runs adversarial attack simulations against LLM endpoints: prompt injection,
jailbreak, data exfiltration, system prompt extraction, privilege escalation,
and PII leakage probes.  Every attack is mapped to OWASP LLM Top 10, MITRE
ATLAS, and NIST AI RMF categories.

NIST 800-53: CA-8 (Penetration Testing), RA-5 (Vulnerability Monitoring).
"""

from modules.redteam.engine import RedTeamEngine, AttackResult, AttackCategory

__all__ = ["RedTeamEngine", "AttackResult", "AttackCategory"]
