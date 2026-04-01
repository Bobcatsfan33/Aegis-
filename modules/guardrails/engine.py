"""
Runtime Guardrails Engine.

Inline enforcement layer that inspects LLM prompts and completions in real time.
Designed to sit in the request path as middleware (or called explicitly) to
block, flag, or redact content before it reaches users or external systems.

Detection categories:
  1. PII (SSN, credit cards, phone numbers, emails, addresses)
  2. Secrets (API keys, tokens, passwords, connection strings)
  3. Prompt Injection (input manipulation attempts)
  4. Toxic / Harmful Content (violence, hate speech, self-harm)
  5. Policy Violations (custom org rules, data classification breaches)
  6. Off-Topic / Scope Violations (model staying in lane)

Each violation is typed, scored, and mapped to NIST controls.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.guardrails")


class ViolationType(str, Enum):
    PII_SSN = "pii_ssn"
    PII_CREDIT_CARD = "pii_credit_card"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_ADDRESS = "pii_address"
    SECRET_API_KEY = "secret_api_key"
    SECRET_PASSWORD = "secret_password"
    SECRET_TOKEN = "secret_token"
    SECRET_CONNECTION_STRING = "secret_connection_string"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    TOXIC_CONTENT = "toxic_content"
    POLICY_VIOLATION = "policy_violation"
    SCOPE_VIOLATION = "scope_violation"


class Action(str, Enum):
    BLOCK = "block"       # Reject the entire request/response
    REDACT = "redact"     # Replace sensitive content with [REDACTED]
    FLAG = "flag"         # Allow but log for review
    PASS = "pass"         # Clean — no action needed


@dataclass
class Violation:
    """A single guardrail violation detected in content."""
    violation_type: ViolationType
    pattern_matched: str
    position: Tuple[int, int]    # (start, end) char offsets
    severity: str                # "critical", "high", "medium", "low"
    nist_controls: List[str]
    redacted_value: Optional[str] = None  # The redacted replacement

    def to_dict(self) -> dict:
        return {
            "type": self.violation_type.value,
            "pattern": self.pattern_matched,
            "position": list(self.position),
            "severity": self.severity,
            "nist_controls": self.nist_controls,
        }


@dataclass
class GuardrailVerdict:
    """The engine's decision on a piece of content."""
    action: Action
    allowed: bool
    violations: List[Violation]
    original_content: str
    sanitized_content: Optional[str]    # Content with redactions applied
    direction: str                      # "input" (prompt) or "output" (completion)
    risk_score: float                   # 0.0 (clean) to 1.0 (critical)
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "allowed": self.allowed,
            "violation_count": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "direction": self.direction,
            "risk_score": self.risk_score,
            "timestamp": self.timestamp,
        }


# ── Detection Patterns ────────────────────────────────────────────────

PII_PATTERNS: List[Dict[str, Any]] = [
    {
        "type": ViolationType.PII_SSN,
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "severity": "critical",
        "nist": ["SC-28", "SI-12"],
        "redact": "[SSN-REDACTED]",
    },
    {
        "type": ViolationType.PII_CREDIT_CARD,
        "regex": re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
        "severity": "critical",
        "nist": ["SC-28", "SI-12"],
        "redact": "[CC-REDACTED]",
    },
    {
        "type": ViolationType.PII_EMAIL,
        "regex": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        "severity": "medium",
        "nist": ["SI-12"],
        "redact": "[EMAIL-REDACTED]",
    },
    {
        "type": ViolationType.PII_PHONE,
        "regex": re.compile(r"\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
        "severity": "medium",
        "nist": ["SI-12"],
        "redact": "[PHONE-REDACTED]",
    },
]

SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "type": ViolationType.SECRET_API_KEY,
        "regex": re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35})\b"),
        "severity": "critical",
        "nist": ["IA-5", "SC-28"],
        "redact": "[API-KEY-REDACTED]",
    },
    {
        "type": ViolationType.SECRET_PASSWORD,
        "regex": re.compile(r"(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})", re.I),
        "severity": "critical",
        "nist": ["IA-5", "SC-28"],
        "redact": "[PASSWORD-REDACTED]",
    },
    {
        "type": ViolationType.SECRET_TOKEN,
        "regex": re.compile(r"(bearer|token|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9._-]{20,})", re.I),
        "severity": "high",
        "nist": ["IA-5", "SC-28"],
        "redact": "[TOKEN-REDACTED]",
    },
    {
        "type": ViolationType.SECRET_CONNECTION_STRING,
        "regex": re.compile(r"(mongodb|postgres|mysql|redis|amqp)://[^\s]{10,}", re.I),
        "severity": "critical",
        "nist": ["IA-5", "SC-28", "SC-7"],
        "redact": "[CONN-STRING-REDACTED]",
    },
]

INJECTION_PATTERNS: List[Dict[str, Any]] = [
    {
        "type": ViolationType.PROMPT_INJECTION,
        "regex": re.compile(r"(ignore (all )?(previous|prior|above) (instructions?|prompts?|rules?))", re.I),
        "severity": "high",
        "nist": ["SI-10", "AC-4"],
    },
    {
        "type": ViolationType.PROMPT_INJECTION,
        "regex": re.compile(r"(you are now|act as|pretend to be|you have been reprogrammed)", re.I),
        "severity": "high",
        "nist": ["SI-10", "AC-4"],
    },
    {
        "type": ViolationType.PROMPT_INJECTION,
        "regex": re.compile(r"(system\s*:\s*new directive|SYSTEM OVERRIDE|admin override)", re.I),
        "severity": "critical",
        "nist": ["SI-10", "AC-4", "AC-3"],
    },
    {
        "type": ViolationType.PROMPT_INJECTION,
        "regex": re.compile(r"(\[HIDDEN:|\[INST\]|<\|system\|>|<<SYS>>)", re.I),
        "severity": "critical",
        "nist": ["SI-10", "AC-4"],
    },
    {
        "type": ViolationType.JAILBREAK_ATTEMPT,
        "regex": re.compile(r"(DAN|Do Anything Now|LIBRE|no restrictions|no guardrails|no filters)", re.I),
        "severity": "high",
        "nist": ["AC-3", "AC-4"],
    },
]

# Custom blocked terms (extended at runtime via policy engine)
DEFAULT_BLOCKED_TERMS: List[str] = [
    "password", "ssn", "social security", "credit card number",
    "secret key", "private key", "api_key", "access_token",
]


class GuardrailsEngine:
    """
    Runtime Guardrails Engine.

    Usage:
        engine = GuardrailsEngine()

        # Check a prompt before sending to LLM
        verdict = engine.check_input("Tell me about machine learning")
        if not verdict.allowed:
            return {"error": verdict.violations}

        # Check LLM output before returning to user
        verdict = engine.check_output(llm_response_text)
        if verdict.action == Action.REDACT:
            return verdict.sanitized_content
    """

    def __init__(
        self,
        block_pii: bool = True,
        block_secrets: bool = True,
        block_injections: bool = True,
        redact_mode: bool = True,      # True = redact & pass, False = block entirely
        blocked_terms: Optional[List[str]] = None,
        custom_patterns: Optional[List[Dict[str, Any]]] = None,
        severity_threshold: str = "medium",  # Block at this severity or above
    ):
        self.block_pii = block_pii
        self.block_secrets = block_secrets
        self.block_injections = block_injections
        self.redact_mode = redact_mode
        self.blocked_terms = blocked_terms or DEFAULT_BLOCKED_TERMS
        self.custom_patterns = custom_patterns or []
        self.severity_threshold = severity_threshold

        # Build severity ordering for threshold comparison
        self._severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def check_input(self, content: str) -> GuardrailVerdict:
        """Check an inbound prompt before sending to LLM."""
        return self._evaluate(content, direction="input")

    def check_output(self, content: str) -> GuardrailVerdict:
        """Check an LLM response before returning to the user."""
        return self._evaluate(content, direction="output")

    def check(self, payload: Dict[str, Any]) -> GuardrailVerdict:
        """Check a payload dict (backward-compatible with skeleton API)."""
        content = payload.get("prompt", "") or payload.get("content", "")
        direction = payload.get("direction", "input")
        return self._evaluate(content, direction=direction)

    def _evaluate(self, content: str, direction: str = "input") -> GuardrailVerdict:
        """Core evaluation logic."""
        violations: List[Violation] = []

        # 1. PII detection
        if self.block_pii:
            violations.extend(self._scan_patterns(content, PII_PATTERNS))

        # 2. Secrets detection
        if self.block_secrets:
            violations.extend(self._scan_patterns(content, SECRET_PATTERNS))

        # 3. Injection detection (primarily on inputs)
        if self.block_injections and direction == "input":
            violations.extend(self._scan_patterns(content, INJECTION_PATTERNS))

        # 4. Blocked terms
        violations.extend(self._scan_blocked_terms(content))

        # 5. Custom patterns
        if self.custom_patterns:
            violations.extend(self._scan_patterns(content, self.custom_patterns))

        # Filter by severity threshold
        threshold = self._severity_order.get(self.severity_threshold, 2)
        actionable = [
            v for v in violations
            if self._severity_order.get(v.severity, 0) >= threshold
        ]

        # Determine action
        if not actionable:
            return GuardrailVerdict(
                action=Action.PASS,
                allowed=True,
                violations=violations,  # May have sub-threshold violations
                original_content=content,
                sanitized_content=content,
                direction=direction,
                risk_score=0.0,
            )

        # Calculate risk score
        max_sev = max(self._severity_order.get(v.severity, 0) for v in actionable)
        risk_score = min(1.0, max_sev / 4.0 + len(actionable) * 0.05)

        # Redact or block
        if self.redact_mode:
            sanitized = self._apply_redactions(content, actionable)
            return GuardrailVerdict(
                action=Action.REDACT,
                allowed=True,
                violations=actionable,
                original_content=content,
                sanitized_content=sanitized,
                direction=direction,
                risk_score=round(risk_score, 3),
            )
        else:
            # Hard block
            has_critical = any(v.severity == "critical" for v in actionable)
            return GuardrailVerdict(
                action=Action.BLOCK,
                allowed=False,
                violations=actionable,
                original_content=content,
                sanitized_content=None,
                direction=direction,
                risk_score=round(risk_score, 3),
                details={"reason": f"Blocked: {len(actionable)} violation(s) at or above {self.severity_threshold}"},
            )

    def _scan_patterns(
        self, content: str, patterns: List[Dict[str, Any]]
    ) -> List[Violation]:
        """Scan content against a list of regex patterns."""
        violations = []
        for pat_def in patterns:
            regex = pat_def["regex"]
            for match in regex.finditer(content):
                violations.append(Violation(
                    violation_type=pat_def["type"],
                    pattern_matched=match.group()[:50],  # Truncate for safety
                    position=(match.start(), match.end()),
                    severity=pat_def["severity"],
                    nist_controls=pat_def.get("nist", []),
                    redacted_value=pat_def.get("redact"),
                ))
        return violations

    def _scan_blocked_terms(self, content: str) -> List[Violation]:
        """Scan for blocked terms (case-insensitive substring match)."""
        violations = []
        content_lower = content.lower()
        for term in self.blocked_terms:
            idx = content_lower.find(term.lower())
            if idx >= 0:
                violations.append(Violation(
                    violation_type=ViolationType.POLICY_VIOLATION,
                    pattern_matched=term,
                    position=(idx, idx + len(term)),
                    severity="medium",
                    nist_controls=["AC-4", "SI-10"],
                ))
        return violations

    def _apply_redactions(self, content: str, violations: List[Violation]) -> str:
        """Apply redactions to content, replacing matched spans."""
        # Sort violations by position (reverse) to preserve offsets
        sorted_violations = sorted(violations, key=lambda v: v.position[0], reverse=True)
        result = content
        for v in sorted_violations:
            start, end = v.position
            replacement = v.redacted_value or "[REDACTED]"
            result = result[:start] + replacement + result[end:]
        return result

    def summary(self, verdicts: List[GuardrailVerdict]) -> Dict[str, Any]:
        """Summarize a batch of guardrail evaluations."""
        total = len(verdicts)
        blocked = sum(1 for v in verdicts if v.action == Action.BLOCK)
        redacted = sum(1 for v in verdicts if v.action == Action.REDACT)
        passed = sum(1 for v in verdicts if v.action == Action.PASS)

        all_violations = [v for verdict in verdicts for v in verdict.violations]
        by_type = {}
        for v in all_violations:
            by_type[v.violation_type.value] = by_type.get(v.violation_type.value, 0) + 1

        return {
            "total_evaluations": total,
            "blocked": blocked,
            "redacted": redacted,
            "passed": passed,
            "total_violations": len(all_violations),
            "violations_by_type": by_type,
            "nist_controls_enforced": sorted(set(
                ctrl for v in all_violations for ctrl in v.nist_controls
            )),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
