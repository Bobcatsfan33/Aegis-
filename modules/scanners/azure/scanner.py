"""
Azure scanner — checks NSGs and Storage Accounts.
Requires:
    pip install azure-identity azure-mgmt-network azure-mgmt-storage
    Set AZURE_SUBSCRIPTION_ID, AZURE_TENANT_ID (+ client id/secret or use DefaultAzureCredential).
"""

import logging
from typing import List

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.storage import StorageManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AzureScanner(BaseScanner):
    provider = "azure"

    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id

    def is_available(self) -> bool:
        if not AZURE_AVAILABLE:
            logger.warning(
                "Azure SDK not installed. "
                "Run: pip install azure-identity azure-mgmt-network azure-mgmt-storage"
            )
            return False
        if not self.subscription_id:
            logger.warning("AZURE_SUBSCRIPTION_ID not set — Azure scanning disabled.")
            return False
        try:
            DefaultAzureCredential()
            return True
        except Exception as e:
            logger.warning(f"Azure credential check failed: {e}")
            return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        checks = [
            self._check_nsg_open_ports,
            self._check_storage_public_access,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as e:
                logger.warning(f"Azure check '{check.__name__}' failed: {e}")
        return findings

    # ── NSG ───────────────────────────────────────────────────────────────────

    def _check_nsg_open_ports(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.subscription_id)

            for nsg in client.network_security_groups.list_all():
                for rule in nsg.security_rules or []:
                    if (
                        rule.access == "Allow"
                        and rule.direction == "Inbound"
                        and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                    ):
                        dest_port = rule.destination_port_range or "*"
                        severity = (
                            "critical" if dest_port in ("22", "3389", "*") else "high"
                        )
                        findings.append(Finding(
                            resource=nsg.id or nsg.name,
                            issue=(
                                f"NSG '{nsg.name}' allows inbound from the internet "
                                f"on port {dest_port} (rule: {rule.name})"
                            ),
                            severity=severity,
                            provider="azure",
                            resource_type="network_security_group",
                            details={
                                "nsg_name": nsg.name,
                                "rule_name": rule.name,
                                "port": dest_port,
                                "source": rule.source_address_prefix,
                            },
                            remediation_hint=(
                                f"Restrict source_address_prefix on NSG rule "
                                f"'{rule.name}' to a specific IP range"
                            ),
                        ))
        except Exception as e:
            logger.error(f"NSG scan failed: {e}")
        return findings

    # ── Storage ───────────────────────────────────────────────────────────────

    def _check_storage_public_access(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            credential = DefaultAzureCredential()
            client = StorageManagementClient(credential, self.subscription_id)

            for account in client.storage_accounts.list():
                if getattr(account, "allow_blob_public_access", False):
                    findings.append(Finding(
                        resource=account.id or account.name,
                        issue=(
                            f"Storage account '{account.name}' allows public blob access"
                        ),
                        severity="high",
                        provider="azure",
                        resource_type="storage_account",
                        details={
                            "name": account.name,
                            "location": account.location,
                        },
                        remediation_hint=(
                            "az storage account update "
                            f"--name {account.name} "
                            "--allow-blob-public-access false"
                        ),
                    ))
        except Exception as e:
            logger.error(f"Storage account scan failed: {e}")
        return findings
