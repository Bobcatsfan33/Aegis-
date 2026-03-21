"""
Cloud Remediation Agent — applies fixes directly to cloud resources.

Supported actions:
  AWS:
    s3_bucket        → block_public_access, set_private_acl
    security_group   → revoke_ingress
    rds_instance     → disable_public_access
  Azure / GCP:
    Dry-run stubs included; live implementation left for environment-specific wiring.
"""

import logging
from modules.scanners.base import Finding
from modules.agents.base import BaseAgent, RemediationResult

logger = logging.getLogger(__name__)

SUPPORTED_RESOURCE_TYPES = {
    "s3_bucket",
    "security_group",
    "rds_instance",
    "cloudtrail",
    "iam",
    "network_security_group",
    "storage_account",
    "firewall_rule",
}


class CloudRemediationAgent(BaseAgent):
    """Remediates cloud misconfigurations across AWS, Azure, and GCP."""

    def can_handle(self, finding: Finding) -> bool:
        return (
            finding.provider in ("aws", "azure", "gcp")
            and finding.resource_type in SUPPORTED_RESOURCE_TYPES
        )

    def remediate(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        dispatch = {
            "aws":   self._remediate_aws,
            "azure": self._remediate_azure,
            "gcp":   self._remediate_gcp,
        }
        handler = dispatch.get(finding.provider)
        if not handler:
            return RemediationResult(
                success=False,
                action_taken="none",
                details=f"No handler for provider '{finding.provider}'",
                dry_run=self.dry_run,
                error="unsupported_provider",
            )
        return handler(finding, action, **kwargs)

    # ── AWS ───────────────────────────────────────────────────────────────────

    def _remediate_aws(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        try:
            import boto3
        except ImportError:
            return RemediationResult(
                False, "none", "boto3 not installed", self.dry_run, "import_error"
            )

        rt = finding.resource_type
        resource = finding.resource

        if rt == "s3_bucket":
            return self._aws_s3_block_public_access(boto3, resource)
        elif rt == "security_group":
            return self._aws_sg_revoke_ingress(boto3, resource, finding)
        elif rt == "rds_instance":
            return self._aws_rds_disable_public(boto3, resource)
        else:
            # For IAM / CloudTrail findings we log guidance but don't auto-change
            return RemediationResult(
                success=True,
                action_taken="guidance_only",
                details=(
                    f"Auto-remediation for AWS '{rt}' requires manual review. "
                    f"See remediation_hint: {finding.remediation_hint}"
                ),
                dry_run=self.dry_run,
            )

    def _aws_s3_block_public_access(self, boto3, bucket_name: str) -> RemediationResult:
        action = "block_public_access"
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would enable all Block Public Access flags on s3://{bucket_name}",
                dry_run=True,
            )
        try:
            s3 = boto3.client("s3")
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return RemediationResult(
                success=True,
                action_taken=action,
                details=f"Block Public Access enabled on s3://{bucket_name}",
                dry_run=False,
            )
        except Exception as e:
            return RemediationResult(False, action, str(e), False, str(e))

    def _aws_sg_revoke_ingress(
        self, boto3, group_id: str, finding: Finding
    ) -> RemediationResult:
        action = "revoke_ingress"
        details = finding.details or {}
        from_port = details.get("from_port", -1)
        to_port = details.get("to_port", -1)
        protocol = details.get("protocol", "-1")

        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=(
                    f"Would revoke open inbound rule 0.0.0.0/0 "
                    f"port {from_port}–{to_port} from {group_id}"
                ),
                dry_run=True,
            )
        try:
            ec2 = boto3.client("ec2")
            ip_perm: dict = {
                "IpProtocol": protocol,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
            if from_port != -1:
                ip_perm["FromPort"] = from_port
                ip_perm["ToPort"] = to_port

            ec2.revoke_security_group_ingress(
                GroupId=group_id,
                IpPermissions=[ip_perm],
            )
            return RemediationResult(
                success=True,
                action_taken=action,
                details=f"Revoked open inbound rule from security group {group_id}",
                dry_run=False,
            )
        except Exception as e:
            return RemediationResult(False, action, str(e), False, str(e))

    def _aws_rds_disable_public(self, boto3, db_id: str) -> RemediationResult:
        action = "disable_public_access"
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would set PubliclyAccessible=False on RDS instance '{db_id}'",
                dry_run=True,
            )
        try:
            rds = boto3.client("rds")
            rds.modify_db_instance(
                DBInstanceIdentifier=db_id,
                PubliclyAccessible=False,
                ApplyImmediately=True,
            )
            return RemediationResult(
                success=True,
                action_taken=action,
                details=f"Public access disabled on RDS instance '{db_id}'",
                dry_run=False,
            )
        except Exception as e:
            return RemediationResult(False, action, str(e), False, str(e))

    # ── Azure ─────────────────────────────────────────────────────────────────

    def _remediate_azure(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"azure_{action} (dry run)",
                details=f"Would remediate Azure resource: {finding.resource}",
                dry_run=True,
            )
        # Live Azure remediation requires resource group context.
        # Implement using azure-mgmt-network / azure-mgmt-storage clients as needed.
        return RemediationResult(
            success=False,
            action_taken="none",
            details=(
                "Azure live remediation requires resource group context. "
                "Implement _remediate_azure with azure-mgmt-* SDK calls."
            ),
            dry_run=False,
            error="not_implemented",
        )

    # ── GCP ───────────────────────────────────────────────────────────────────

    def _remediate_gcp(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"gcp_{action} (dry run)",
                details=f"Would remediate GCP resource: {finding.resource}",
                dry_run=True,
            )
        return RemediationResult(
            success=False,
            action_taken="none",
            details=(
                "GCP live remediation requires project context. "
                "Implement _remediate_gcp with google-cloud-compute SDK calls."
            ),
            dry_run=False,
            error="not_implemented",
        )
