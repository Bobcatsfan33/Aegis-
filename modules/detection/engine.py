"""
Threat Detection Engine — YAML-based rule evaluation for network traffic analysis.

Supports multiple condition types:
  - threshold:  Event count within sliding window (stateful)
  - pattern:    Regex matching on event fields
  - anomaly:    Statistical deviation from baseline
  - static:     Direct field comparisons (eq, gt, lt, in, not_in)

Thread-safe with in-memory state tracking for sliding windows and cooldown timers.
Production-quality error handling and logging throughout.
"""

import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from modules.scanners.base import Finding

logger = logging.getLogger(__name__)


# ── Data classes ────────────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    """A single threat detection rule loaded from YAML."""

    rule_id: str
    name: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    category: str  # "reconnaissance" | "brute_force" | "c2_beaconing" | "data_exfiltration" | "lateral_movement" | "rogue_device" | "policy_violation"
    mitre_technique: str  # e.g., "T1046"
    nist_control: str  # e.g., "SI-4"
    conditions: Dict[str, Any]  # Matching criteria
    actions: List[str] = field(default_factory=lambda: ["alert", "log"])  # "alert" | "block" | "log"
    enabled: bool = True
    cooldown_seconds: int = 300
    cwe_id: Optional[str] = None


@dataclass
class DetectionEvent:
    """A network traffic event to be evaluated against detection rules."""

    timestamp: datetime
    rule_id: Optional[str] = None  # Set if triggered; otherwise None
    source_ip: str = ""
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    payload_size: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Internal state classes ──────────────────────────────────────────────────

@dataclass
class _RuleState:
    """Per-rule internal state tracking for threshold windows and cooldowns."""

    rule_id: str
    # Sliding window: group_by_key -> list of (timestamp, event) tuples
    sliding_windows: Dict[str, List[tuple]] = field(default_factory=lambda: defaultdict(list))
    # Cooldown tracking: group_by_key -> last_trigger_time
    last_trigger_times: Dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


# ── Condition evaluator ─────────────────────────────────────────────────────

class _ConditionEvaluator:
    """Evaluates various condition types against detection events."""

    @staticmethod
    def evaluate_threshold(
        condition: Dict[str, Any],
        event: DetectionEvent,
        rule_state: _RuleState,
    ) -> bool:
        """
        Threshold condition: triggers when count events matching criteria
        occur within a sliding time window.

        condition = {
            "type": "threshold",
            "count": 20,
            "window_seconds": 60,
            "group_by": "source_ip" | "dest_ip" | "dest_port",
            "filter": { optional field comparisons }
        }
        """
        try:
            count = condition.get("count", 1)
            window_seconds = condition.get("window_seconds", 60)
            group_by = condition.get("group_by", "source_ip")
            filter_criteria = condition.get("filter", {})

            # Determine grouping key
            if group_by == "source_ip":
                group_key = event.source_ip
            elif group_by == "dest_ip":
                group_key = event.dest_ip or "unknown"
            elif group_by == "dest_port":
                group_key = str(event.dest_port or "unknown")
            else:
                logger.warning(f"Unknown group_by: {group_by}")
                return False

            now = time.time()
            with rule_state.lock:
                # Clean old entries outside the window
                window_start = now - window_seconds
                window = rule_state.sliding_windows[group_key]
                window[:] = [(ts, ev) for ts, ev in window if ts > window_start]

                # Add current event
                window.append((now, event))

                # Count events matching filter criteria
                matching = 0
                for ts, ev in window:
                    if _ConditionEvaluator._matches_filter(ev, filter_criteria):
                        matching += 1

                return matching >= count

        except Exception as e:
            logger.error(f"Error evaluating threshold condition: {e}")
            return False

    @staticmethod
    def evaluate_pattern(condition: Dict[str, Any], event: DetectionEvent) -> bool:
        """
        Pattern condition: triggers on regex match against a field.

        condition = {
            "type": "pattern",
            "field": "protocol" | "source_ip" | "dest_ip" | other event field,
            "regex": r"^TCP$" | other regex
        }
        """
        try:
            field_name = condition.get("field", "")
            regex_pattern = condition.get("regex", "")

            if not field_name or not regex_pattern:
                logger.warning("Pattern condition missing field or regex")
                return False

            field_value = getattr(event, field_name, None)
            if field_value is None:
                return False

            return bool(re.search(regex_pattern, str(field_value)))

        except Exception as e:
            logger.error(f"Error evaluating pattern condition: {e}")
            return False

    @staticmethod
    def evaluate_anomaly(condition: Dict[str, Any], event: DetectionEvent) -> bool:
        """
        Anomaly condition: triggers when value exceeds baseline by factor.
        (Simplified: requires baseline_key to be passed at evaluation time)

        condition = {
            "type": "anomaly",
            "field": "payload_size",
            "baseline_key": "avg_payload_size",
            "deviation_factor": 3.0  # Trigger if value > baseline * factor
        }

        Note: Full implementation would integrate with a metrics store.
        This stub returns False; extend with baseline integration.
        """
        try:
            # Placeholder: integration with metrics store would go here
            logger.debug("Anomaly detection requires external baseline store (not yet integrated)")
            return False
        except Exception as e:
            logger.error(f"Error evaluating anomaly condition: {e}")
            return False

    @staticmethod
    def evaluate_static(condition: Dict[str, Any], event: DetectionEvent) -> bool:
        """
        Static condition: direct field comparison.

        condition = {
            "type": "static",
            "field": "protocol",
            "operator": "eq" | "gt" | "lt" | "in" | "not_in",
            "value": "TCP" | 443 | ["SSH", "Telnet"] | other
        }
        """
        try:
            field_name = condition.get("field", "")
            operator = condition.get("operator", "eq")
            value = condition.get("value")

            if not field_name:
                logger.warning("Static condition missing field")
                return False

            field_value = getattr(event, field_name, None)

            if operator == "eq":
                return field_value == value
            elif operator == "gt":
                return field_value > value if field_value is not None else False
            elif operator == "lt":
                return field_value < value if field_value is not None else False
            elif operator == "in":
                return field_value in value if isinstance(value, (list, tuple, set)) else False
            elif operator == "not_in":
                return field_value not in value if isinstance(value, (list, tuple, set)) else True
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False

        except Exception as e:
            logger.error(f"Error evaluating static condition: {e}")
            return False

    @staticmethod
    def _matches_filter(event: DetectionEvent, filter_criteria: Dict[str, Any]) -> bool:
        """Check if event matches optional filter criteria."""
        if not filter_criteria:
            return True

        # Simple implementation: all filter conditions must match
        for key, value in filter_criteria.items():
            if key == "unique_field":
                # Special key: count unique values of this field
                continue
            event_value = getattr(event, key, None)
            if event_value != value:
                return False
        return True


# ── Main engine ─────────────────────────────────────────────────────────────

class RuleEngine:
    """
    YAML-based threat detection rule engine for network traffic analysis.

    Features:
    - Loads all .yaml files from a rules directory
    - Evaluates events against enabled rules
    - Maintains per-rule state for stateful detection (sliding windows, cooldowns)
    - Thread-safe state management
    - Comprehensive error handling and logging
    """

    def __init__(self, rules_dir: str):
        """
        Initialize the rule engine.

        Args:
            rules_dir: Directory containing .yaml rule files
        """
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, DetectionRule] = {}
        self.rule_states: Dict[str, _RuleState] = {}
        self.evaluator = _ConditionEvaluator()
        self._lock = threading.Lock()

        logger.info(f"Initializing RuleEngine with rules_dir: {self.rules_dir}")
        self._load_rules()

    def _load_rules(self) -> None:
        """Load all .yaml rule files from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory does not exist: {self.rules_dir}")
            return

        rule_files = sorted(self.rules_dir.glob("*.yaml")) + sorted(self.rules_dir.glob("*.yml"))
        logger.info(f"Found {len(rule_files)} rule file(s) in {self.rules_dir}")

        for rule_file in rule_files:
            try:
                with open(rule_file, "r") as f:
                    rule_data = yaml.safe_load(f)

                if not rule_data:
                    logger.warning(f"Empty rule file: {rule_file}")
                    continue

                rule = self._parse_rule(rule_data)
                if rule:
                    self.rules[rule.rule_id] = rule
                    self.rule_states[rule.rule_id] = _RuleState(rule_id=rule.rule_id)
                    logger.info(f"Loaded rule: {rule.rule_id} ({rule.name})")

            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")

    def _parse_rule(self, rule_data: Dict[str, Any]) -> Optional[DetectionRule]:
        """Parse a rule from YAML data, with validation."""
        try:
            required_fields = [
                "rule_id", "name", "description", "severity", "category",
                "mitre_technique", "nist_control", "conditions"
            ]
            for field in required_fields:
                if field not in rule_data:
                    logger.error(f"Rule missing required field: {field}")
                    return None

            # Validate severity
            if rule_data["severity"] not in ["critical", "high", "medium", "low", "info"]:
                logger.error(f"Invalid severity: {rule_data['severity']}")
                return None

            # Validate category
            valid_categories = [
                "reconnaissance", "brute_force", "c2_beaconing",
                "data_exfiltration", "lateral_movement", "rogue_device",
                "policy_violation"
            ]
            if rule_data["category"] not in valid_categories:
                logger.error(f"Invalid category: {rule_data['category']}")
                return None

            return DetectionRule(
                rule_id=rule_data["rule_id"],
                name=rule_data["name"],
                description=rule_data["description"],
                severity=rule_data["severity"],
                category=rule_data["category"],
                mitre_technique=rule_data["mitre_technique"],
                nist_control=rule_data["nist_control"],
                conditions=rule_data.get("conditions", {}),
                actions=rule_data.get("actions", ["alert", "log"]),
                enabled=rule_data.get("enabled", True),
                cooldown_seconds=rule_data.get("cooldown_seconds", 300),
                cwe_id=rule_data.get("cwe_id"),
            )

        except Exception as e:
            logger.error(f"Error parsing rule: {e}")
            return None

    def load_rules(self) -> List[DetectionRule]:
        """Return list of all loaded rules."""
        return list(self.rules.values())

    def evaluate(self, event: DetectionEvent) -> List[Finding]:
        """
        Evaluate a detection event against all enabled rules.

        Returns a list of Findings for rules that match.

        Thread-safe: uses per-rule locks for state management.

        Args:
            event: The network traffic event to evaluate

        Returns:
            List of Finding objects for triggered rules
        """
        findings = []

        with self._lock:
            enabled_rules = {
                rid: rule for rid, rule in self.rules.items() if rule.enabled
            }

        for rule_id, rule in enabled_rules.items():
            try:
                rule_state = self.rule_states[rule_id]

                # Check cooldown
                if not self._check_cooldown(event, rule, rule_state):
                    continue

                # Evaluate conditions
                if self._evaluate_conditions(event, rule, rule_state):
                    finding = self._create_finding(event, rule)
                    findings.append(finding)

                    # Update last trigger time
                    group_key = self._get_group_key(event, rule)
                    with rule_state.lock:
                        rule_state.last_trigger_times[group_key] = time.time()

                    logger.info(f"Rule triggered: {rule_id} ({rule.name}) for source {event.source_ip}")

            except Exception as e:
                logger.error(f"Error evaluating rule {rule_id}: {e}")

        return findings

    def _check_cooldown(
        self, event: DetectionEvent, rule: DetectionRule, rule_state: _RuleState
    ) -> bool:
        """Check if enough time has passed since last trigger for this rule/source."""
        group_key = self._get_group_key(event, rule)

        with rule_state.lock:
            last_trigger = rule_state.last_trigger_times.get(group_key, 0)

        now = time.time()
        time_since_trigger = now - last_trigger

        return time_since_trigger >= rule.cooldown_seconds

    def _get_group_key(self, event: DetectionEvent, rule: DetectionRule) -> str:
        """Extract the grouping key from event based on rule's group_by."""
        conditions = rule.conditions
        group_by = conditions.get("group_by", "source_ip")

        if group_by == "source_ip":
            return event.source_ip
        elif group_by == "dest_ip":
            return event.dest_ip or "unknown"
        elif group_by == "dest_port":
            return str(event.dest_port or "unknown")
        else:
            return event.source_ip

    def _evaluate_conditions(
        self, event: DetectionEvent, rule: DetectionRule, rule_state: _RuleState
    ) -> bool:
        """Evaluate all conditions in a rule against an event."""
        conditions = rule.conditions
        condition_type = conditions.get("type", "static")

        if condition_type == "threshold":
            return self.evaluator.evaluate_threshold(conditions, event, rule_state)
        elif condition_type == "pattern":
            return self.evaluator.evaluate_pattern(conditions, event)
        elif condition_type == "anomaly":
            return self.evaluator.evaluate_anomaly(conditions, event)
        elif condition_type == "static":
            return self.evaluator.evaluate_static(conditions, event)
        else:
            logger.warning(f"Unknown condition type: {condition_type}")
            return False

    def _create_finding(self, event: DetectionEvent, rule: DetectionRule) -> Finding:
        """Create a Finding object from a triggered rule and event."""
        return Finding(
            resource=event.source_ip,
            issue=rule.description,
            severity=rule.severity,
            provider="network",
            resource_type="network_host",
            details={
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "category": rule.category,
                "source_ip": event.source_ip,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "payload_size": event.payload_size,
                "event_metadata": event.metadata,
            },
            remediation_hint=f"Review {rule.category} activity from {event.source_ip}",
            mitre_techniques=[rule.mitre_technique],
            mitre_tactic="",  # Could be derived from technique if needed
            nist_controls=[rule.nist_control],
            cwe_id=rule.cwe_id,
        )

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Retrieve a rule by ID."""
        return self.rules.get(rule_id)

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID."""
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = True
            logger.info(f"Enabled rule: {rule_id}")
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID."""
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = False
            logger.info(f"Disabled rule: {rule_id}")
            return True
        return False

    def list_rules(self) -> Dict[str, str]:
        """List all rules with their status."""
        return {
            rule_id: f"{rule.name} ({'enabled' if rule.enabled else 'disabled'})"
            for rule_id, rule in self.rules.items()
        }
