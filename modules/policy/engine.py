"""
AI Governance & Policy Engine.

Centralized rule engine that evaluates AI events against configurable policies.
Produces risk assessments with severity, compliance mapping, and recommended
actions.  Rules cover:

  - Model usage restrictions (approved models, providers, endpoints)
  - Data classification enforcement (what data can flow to which models)
  - Access control patterns (who can invoke which AI capabilities)
  - Rate anomaly detection (unusual token consumption, request spikes)
  - Regulatory alignment (EU AI Act risk tiers, NIST AI RMF, EO 14110)
  - Cost governance (budget thresholds, per-user limits)

Integrates with: guardrails (enforcement), telemetry (logging),
discovery (inventory), and red team (vulnerability context).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("aegis.policy")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleAction(str, Enum):
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"
    QUARANTINE = "quarantine"


class ComplianceFramework(str, Enum):
    NIST_AI_RMF = "nist_ai_rmf"
    NIST_800_53 = "nist_800_53"
    EU_AI_ACT = "eu_ai_act"
    EO_14110 = "eo_14110"
    OWASP_LLM = "owasp_llm_top10"
    ISO_42001 = "iso_42001"


@dataclass
class PolicyRule:
    """A single governance rule."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    action: RuleAction
    frameworks: List[ComplianceFramework]
    nist_controls: List[str]
    evaluate: Optional[Callable] = None  # Custom eval function
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "action": self.action.value,
            "frameworks": [f.value for f in self.frameworks],
            "nist_controls": self.nist_controls,
            "enabled": self.enabled,
        }


@dataclass
class RuleViolation:
    """A single rule violation within an assessment."""
    rule: PolicyRule
    evidence: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskAssessment:
    """Complete risk assessment for an AI event."""
    event_type: str
    overall_severity: Severity
    overall_score: float          # 0-100
    violations: List[RuleViolation]
    action: RuleAction            # Highest-priority action from violated rules
    compliant: bool
    frameworks_evaluated: List[str]
    nist_controls_violated: List[str]
    recommendations: List[str]
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "overall_severity": self.overall_severity.value,
            "overall_score": self.overall_score,
            "violation_count": len(self.violations),
            "violations": [
                {"rule_id": v.rule.rule_id, "name": v.rule.name,
                 "severity": v.rule.severity.value, "evidence": v.evidence}
                for v in self.violations
            ],
            "action": self.action.value,
            "compliant": self.compliant,
            "frameworks_evaluated": self.frameworks_evaluated,
            "nist_controls_violated": self.nist_controls_violated,
            "recommendations": self.recommendations,
            "timestamp": self.timestamp,
        }


# ── Built-in Rule Evaluators ─────────────────────────────────────────

def _eval_unapproved_model(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Check if the model used is on the approved list."""
    model = event.get("model", "")
    approved = config.get("approved_models", [])
    if approved and model and model not in approved:
        return f"Model '{model}' is not on the approved list: {approved}"
    return None


def _eval_unapproved_provider(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Check if the provider is approved."""
    provider = event.get("provider", "")
    approved = config.get("approved_providers", [])
    if approved and provider and provider not in approved:
        return f"Provider '{provider}' is not approved: {approved}"
    return None


def _eval_high_token_usage(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Flag unusually high token consumption."""
    tokens = event.get("total_tokens", 0)
    threshold = config.get("max_tokens_per_request", 50000)
    if tokens > threshold:
        return f"Token usage ({tokens}) exceeds threshold ({threshold})"
    return None


def _eval_sensitive_data_to_external(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Flag if classified data is sent to an external model."""
    data_class = event.get("data_classification", "")
    provider = event.get("provider", "")
    external = config.get("external_providers", ["openai", "anthropic", "google"])
    restricted_classes = config.get("external_restricted_classifications", ["secret", "top_secret", "pii", "phi"])
    if data_class.lower() in restricted_classes and provider in external:
        return f"Data classified as '{data_class}' sent to external provider '{provider}'"
    return None


def _eval_admin_prompt_keywords(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Detect admin/privilege keywords in prompts."""
    prompt = event.get("prompt", "").lower()
    keywords = ["admin", "root", "sudo", "superuser", "override", "bypass"]
    found = [k for k in keywords if k in prompt]
    if found:
        return f"Privilege-related keywords detected in prompt: {found}"
    return None


def _eval_confidential_in_response(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Check if response contains confidentiality markers."""
    response = event.get("response", "").lower()
    markers = ["confidential", "internal only", "do not distribute", "classified", "fouo"]
    found = [m for m in markers if m in response]
    if found:
        return f"Confidentiality markers in response: {found}"
    return None


def _eval_cost_threshold(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Flag if cost exceeds per-request or daily threshold."""
    cost = event.get("cost_usd", 0.0)
    max_per_request = config.get("max_cost_per_request_usd", 1.0)
    if cost > max_per_request:
        return f"Request cost ${cost:.4f} exceeds threshold ${max_per_request:.4f}"
    return None


def _eval_rate_anomaly(event: Dict[str, Any], config: Dict[str, Any]) -> Optional[str]:
    """Flag if request rate is anomalous for the user/service."""
    requests_in_window = event.get("requests_in_window", 0)
    max_rate = config.get("max_requests_per_minute", 60)
    if requests_in_window > max_rate:
        return f"Request rate ({requests_in_window}/min) exceeds limit ({max_rate}/min)"
    return None


# ── Default Rule Set ──────────────────────────────────────────────────

DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule(
        rule_id="GOV-001",
        name="Unapproved AI Model",
        description="Blocks usage of models not on the organization's approved list",
        severity=Severity.HIGH,
        action=RuleAction.BLOCK,
        frameworks=[ComplianceFramework.NIST_AI_RMF, ComplianceFramework.ISO_42001],
        nist_controls=["CM-7", "SA-9"],
        evaluate=_eval_unapproved_model,
    ),
    PolicyRule(
        rule_id="GOV-002",
        name="Unapproved Provider",
        description="Blocks requests to non-approved AI providers",
        severity=Severity.HIGH,
        action=RuleAction.BLOCK,
        frameworks=[ComplianceFramework.NIST_AI_RMF, ComplianceFramework.EU_AI_ACT],
        nist_controls=["SA-9", "SC-7"],
        evaluate=_eval_unapproved_provider,
    ),
    PolicyRule(
        rule_id="GOV-003",
        name="Excessive Token Consumption",
        description="Flags requests with unusually high token usage (DoS indicator)",
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.OWASP_LLM],
        nist_controls=["SC-5", "AU-12"],
        evaluate=_eval_high_token_usage,
    ),
    PolicyRule(
        rule_id="GOV-004",
        name="Sensitive Data to External Provider",
        description="Blocks classified data from being sent to external AI providers",
        severity=Severity.CRITICAL,
        action=RuleAction.BLOCK,
        frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.EU_AI_ACT, ComplianceFramework.EO_14110],
        nist_controls=["AC-4", "SC-7", "SC-28"],
        evaluate=_eval_sensitive_data_to_external,
    ),
    PolicyRule(
        rule_id="GOV-005",
        name="Admin/Privilege Keywords in Prompt",
        description="Flags prompts containing privilege escalation language",
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        frameworks=[ComplianceFramework.OWASP_LLM, ComplianceFramework.NIST_800_53],
        nist_controls=["AC-6", "AU-12"],
        evaluate=_eval_admin_prompt_keywords,
    ),
    PolicyRule(
        rule_id="GOV-006",
        name="Confidential Data in Response",
        description="Flags responses containing confidentiality markers",
        severity=Severity.HIGH,
        action=RuleAction.ALERT,
        frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.EU_AI_ACT],
        nist_controls=["AC-4", "SC-28"],
        evaluate=_eval_confidential_in_response,
    ),
    PolicyRule(
        rule_id="GOV-007",
        name="Cost Threshold Exceeded",
        description="Flags requests exceeding per-request cost limits",
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        frameworks=[ComplianceFramework.NIST_AI_RMF, ComplianceFramework.ISO_42001],
        nist_controls=["SA-9"],
        evaluate=_eval_cost_threshold,
    ),
    PolicyRule(
        rule_id="GOV-008",
        name="Rate Anomaly Detected",
        description="Flags abnormal request rates indicating abuse or compromise",
        severity=Severity.HIGH,
        action=RuleAction.QUARANTINE,
        frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.OWASP_LLM],
        nist_controls=["SC-5", "SI-4", "AU-6"],
        evaluate=_eval_rate_anomaly,
    ),
]


class PolicyEngine:
    """
    AI Governance & Policy Engine.

    Usage:
        engine = PolicyEngine()

        # Add custom rules or config
        engine.configure(approved_models=["gpt-4o", "claude-sonnet-4-6"])

        # Evaluate an AI event
        assessment = engine.evaluate({
            "model": "gpt-3.5-turbo",
            "provider": "openai",
            "prompt": "Tell me about admin access",
            "total_tokens": 150,
        })

        if not assessment.compliant:
            # Take action based on assessment.action
            ...
    """

    def __init__(
        self,
        rules: Optional[List[PolicyRule]] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.rules = rules or list(DEFAULT_RULES)
        self.config = config or {}

    def configure(self, **kwargs):
        """Update policy configuration."""
        self.config.update(kwargs)

    def add_rule(self, rule: PolicyRule):
        """Add a custom policy rule."""
        self.rules.append(rule)
        logger.info("Added policy rule: %s", rule.rule_id)

    def evaluate(self, event: Dict[str, Any]) -> RiskAssessment:
        """Evaluate an AI event against all enabled rules."""
        violations: List[RuleViolation] = []
        frameworks_seen = set()
        nist_violated = set()

        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.evaluate:
                evidence = rule.evaluate(event, self.config)
                if evidence:
                    violations.append(RuleViolation(
                        rule=rule,
                        evidence=evidence,
                    ))
                    frameworks_seen.update(f.value for f in rule.frameworks)
                    nist_violated.update(rule.nist_controls)

        # Calculate overall severity and score
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        if violations:
            max_severity = max(violations, key=lambda v: severity_order.get(v.rule.severity.value, 0))
            overall = max_severity.rule.severity
            score = min(100.0, sum(
                severity_order.get(v.rule.severity.value, 0) * 15 + 10
                for v in violations
            ))
        else:
            overall = Severity.INFO
            score = 0.0

        # Determine action (highest priority from violations)
        action_priority = {RuleAction.LOG: 0, RuleAction.ALERT: 1, RuleAction.QUARANTINE: 2, RuleAction.BLOCK: 3}
        if violations:
            action = max(
                (v.rule.action for v in violations),
                key=lambda a: action_priority.get(a, 0),
            )
        else:
            action = RuleAction.LOG

        # Generate recommendations
        recommendations = []
        for v in violations:
            if v.rule.action == RuleAction.BLOCK:
                recommendations.append(f"[BLOCK] {v.rule.name}: {v.evidence}")
            elif v.rule.action == RuleAction.QUARANTINE:
                recommendations.append(f"[QUARANTINE] {v.rule.name}: Isolate and investigate — {v.evidence}")
            elif v.rule.action == RuleAction.ALERT:
                recommendations.append(f"[ALERT] {v.rule.name}: {v.evidence}")

        return RiskAssessment(
            event_type=event.get("event_type", "ai_request"),
            overall_severity=overall,
            overall_score=round(score, 1),
            violations=violations,
            action=action,
            compliant=len(violations) == 0,
            frameworks_evaluated=sorted(frameworks_seen),
            nist_controls_violated=sorted(nist_violated),
            recommendations=recommendations,
        )

    def evaluate_batch(self, events: List[Dict[str, Any]]) -> List[RiskAssessment]:
        """Evaluate multiple events."""
        return [self.evaluate(e) for e in events]

    def summary(self, assessments: List[RiskAssessment]) -> Dict[str, Any]:
        """Summarize a batch of risk assessments."""
        total = len(assessments)
        compliant = sum(1 for a in assessments if a.compliant)
        by_severity = {}
        by_action = {}
        all_violations = []

        for a in assessments:
            sev = a.overall_severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            act = a.action.value
            by_action[act] = by_action.get(act, 0) + 1
            all_violations.extend(a.violations)

        rule_freq = {}
        for v in all_violations:
            rule_freq[v.rule.rule_id] = rule_freq.get(v.rule.rule_id, 0) + 1

        return {
            "total_events": total,
            "compliant": compliant,
            "non_compliant": total - compliant,
            "compliance_rate": round(compliant / total * 100, 1) if total > 0 else 100.0,
            "by_severity": by_severity,
            "by_action": by_action,
            "top_violated_rules": sorted(rule_freq.items(), key=lambda x: x[1], reverse=True)[:10],
            "nist_controls_violated": sorted(set(
                ctrl for a in assessments for ctrl in a.nist_controls_violated
            )),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def list_rules(self) -> List[Dict[str, Any]]:
        """Return all configured rules."""
        return [r.to_dict() for r in self.rules]
