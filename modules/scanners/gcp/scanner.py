"""
GCP scanner — checks Compute Engine firewall rules.
Requires:
    pip install google-cloud-compute
    Set GCP_PROJECT_ID and configure Application Default Credentials:
    gcloud auth application-default login
"""

import logging
from typing import List

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    from google.cloud import compute_v1
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False


class GCPScanner(BaseScanner):
    provider = "gcp"

    def __init__(self, project_id: str):
        self.project_id = project_id

    def is_available(self) -> bool:
        if not GCP_AVAILABLE:
            logger.warning(
                "GCP SDK not installed. Run: pip install google-cloud-compute"
            )
            return False
        if not self.project_id:
            logger.warning("GCP_PROJECT_ID not set — GCP scanning disabled.")
            return False
        try:
            # Light connectivity check
            compute_v1.ProjectsClient().get(project=self.project_id)
            return True
        except Exception as e:
            logger.warning(f"GCP credential check failed: {e}")
            return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        checks = [
            self._check_firewall_rules,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as e:
                logger.warning(f"GCP check '{check.__name__}' failed: {e}")
        return findings

    # ── Firewall rules ────────────────────────────────────────────────────────

    def _check_firewall_rules(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            client = compute_v1.FirewallsClient()
            for rule in client.list(project=self.project_id):
                if rule.direction != "INGRESS" or rule.disabled:
                    continue
                for ip_range in rule.source_ranges or []:
                    if ip_range not in ("0.0.0.0/0", "::/0"):
                        continue
                    for allowed in rule.allowed or []:
                        ports = list(allowed.ports) if allowed.ports else ["all"]
                        severity = (
                            "critical"
                            if any(p in ("22", "3389") for p in ports)
                            else "high"
                        )
                        findings.append(Finding(
                            resource=rule.self_link or rule.name,
                            issue=(
                                f"GCP firewall rule '{rule.name}' allows public "
                                f"inbound on ports {ports}"
                            ),
                            severity=severity,
                            provider="gcp",
                            resource_type="firewall_rule",
                            details={
                                "rule_name": rule.name,
                                "network": rule.network,
                                "ports": ports,
                                "source_ranges": list(rule.source_ranges),
                            },
                            remediation_hint=(
                                f"gcloud compute firewall-rules update {rule.name} "
                                f"--source-ranges=<specific-ip>/32"
                            ),
                        ))
        except Exception as e:
            logger.error(f"GCP firewall rule scan failed: {e}")
        return findings
