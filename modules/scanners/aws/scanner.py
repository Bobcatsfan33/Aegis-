"""
AWS scanner — checks S3, EC2 security groups, IAM, CloudTrail, and RDS.
Requires: boto3, AWS credentials configured via `aws configure` or environment variables.
"""

import csv
import io
import logging
import time
from typing import List

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class AWSScanner(BaseScanner):
    provider = "aws"

    def is_available(self) -> bool:
        if not BOTO3_AVAILABLE:
            logger.warning("boto3 is not installed — AWS scanning disabled.")
            return False
        try:
            boto3.client("sts").get_caller_identity()
            return True
        except Exception as e:
            logger.warning(f"AWS credentials not available: {e}")
            return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        checks = [
            self._check_s3_public_access,
            self._check_security_groups,
            self._check_iam_root,
            self._check_cloudtrail,
            self._check_rds_public,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as e:
                logger.warning(f"AWS check '{check.__name__}' failed: {e}")
        return findings

    # ── S3 ────────────────────────────────────────────────────────────────────

    def _check_s3_public_access(self) -> List[Finding]:
        findings: List[Finding] = []
        s3 = boto3.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            logger.error(f"Could not list S3 buckets: {e}")
            return findings

        for bucket in buckets:
            name = bucket["Name"]

            # 1. Block Public Access settings (modern, preferred check)
            try:
                bpa = s3.get_public_access_block(Bucket=name)
                cfg = bpa.get("PublicAccessBlockConfiguration", {})
                if not all([
                    cfg.get("BlockPublicAcls", False),
                    cfg.get("IgnorePublicAcls", False),
                    cfg.get("BlockPublicPolicy", False),
                    cfg.get("RestrictPublicBuckets", False),
                ]):
                    findings.append(Finding(
                        resource=name,
                        issue="S3 bucket is missing full Block Public Access configuration",
                        severity="high",
                        provider="aws",
                        resource_type="s3_bucket",
                        details={"block_public_access": cfg},
                        remediation_hint=(
                            "Run: aws s3api put-public-access-block --bucket "
                            f"{name} --public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                    ))
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(Finding(
                        resource=name,
                        issue="S3 bucket has no Block Public Access configuration at all",
                        severity="high",
                        provider="aws",
                        resource_type="s3_bucket",
                        remediation_hint=(
                            f"Enable Block Public Access on s3://{name}"
                        ),
                    ))

            # 2. Legacy ACL check
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        findings.append(Finding(
                            resource=name,
                            issue="S3 bucket ACL grants public access",
                            severity="critical",
                            provider="aws",
                            resource_type="s3_bucket",
                            details={
                                "grantee_uri": uri,
                                "permission": grant.get("Permission"),
                            },
                            remediation_hint=(
                                f"Remove public grants: "
                                f"aws s3api put-bucket-acl --bucket {name} --acl private"
                            ),
                        ))
                        break
            except ClientError as e:
                if e.response["Error"]["Code"] != "AccessDenied":
                    logger.debug(f"Could not get ACL for {name}: {e}")

        return findings

    # ── Security Groups ───────────────────────────────────────────────────────

    def _check_security_groups(self) -> List[Finding]:
        findings: List[Finding] = []
        ec2 = boto3.client("ec2")

        try:
            groups = ec2.describe_security_groups().get("SecurityGroups", [])
        except Exception as e:
            logger.error(f"Could not describe security groups: {e}")
            return findings

        for group in groups:
            group_id = group["GroupId"]
            group_name = group.get("GroupName", group_id)

            for perm in group.get("IpPermissions", []):
                from_port = perm.get("FromPort", -1)
                to_port = perm.get("ToPort", -1)
                protocol = perm.get("IpProtocol", "-1")

                # IPv4 open-to-world
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        severity = (
                            "critical"
                            if from_port in (22, 3389, -1)
                            else "high"
                        )
                        findings.append(Finding(
                            resource=group_id,
                            issue=(
                                f"Security group '{group_name}' allows inbound "
                                f"from 0.0.0.0/0 on port(s) {from_port}–{to_port}"
                            ),
                            severity=severity,
                            provider="aws",
                            resource_type="security_group",
                            details={
                                "group_name": group_name,
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": "0.0.0.0/0",
                            },
                            remediation_hint=(
                                f"aws ec2 revoke-security-group-ingress "
                                f"--group-id {group_id} --protocol {protocol} "
                                f"--port {from_port} --cidr 0.0.0.0/0"
                            ),
                        ))

                # IPv6 open-to-world
                for ipv6_range in perm.get("Ipv6Ranges", []):
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        findings.append(Finding(
                            resource=group_id,
                            issue=(
                                f"Security group '{group_name}' allows inbound "
                                f"from ::/0 (all IPv6) on port(s) {from_port}–{to_port}"
                            ),
                            severity="high",
                            provider="aws",
                            resource_type="security_group",
                            details={"group_name": group_name, "cidr": "::/0"},
                            remediation_hint="Restrict inbound IPv6 rules to known ranges",
                        ))

        return findings

    # ── IAM ───────────────────────────────────────────────────────────────────

    def _check_iam_root(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            iam = boto3.client("iam")
            summary = iam.get_account_summary().get("SummaryMap", {})

            if not summary.get("AccountMFAEnabled", 0):
                findings.append(Finding(
                    resource="aws-root-account",
                    issue="Root account MFA is NOT enabled",
                    severity="critical",
                    provider="aws",
                    resource_type="iam",
                    remediation_hint="Enable MFA on the root account via AWS Console → Security credentials",
                ))

            # Credential report: check for active root access keys
            try:
                iam.generate_credential_report()
                time.sleep(3)
                report = iam.get_credential_report()
                content = report["Content"].decode("utf-8")
                reader = csv.DictReader(io.StringIO(content))
                for row in reader:
                    if row.get("user") == "<root_account>":
                        if (
                            row.get("access_key_1_active") == "true"
                            or row.get("access_key_2_active") == "true"
                        ):
                            findings.append(Finding(
                                resource="aws-root-account",
                                issue="Root account has active programmatic access keys",
                                severity="critical",
                                provider="aws",
                                resource_type="iam",
                                remediation_hint=(
                                    "Delete root access keys: AWS Console → "
                                    "Security credentials → Access keys"
                                ),
                            ))
            except Exception as e:
                logger.debug(f"Could not generate IAM credential report: {e}")

        except Exception as e:
            logger.warning(f"IAM root check failed: {e}")

        return findings

    # ── CloudTrail ────────────────────────────────────────────────────────────

    def _check_cloudtrail(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            ct = boto3.client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])

            if not trails:
                findings.append(Finding(
                    resource="aws-account",
                    issue="No CloudTrail trails configured — no audit log of API activity",
                    severity="high",
                    provider="aws",
                    resource_type="cloudtrail",
                    remediation_hint=(
                        "aws cloudtrail create-trail --name default "
                        "--s3-bucket-name <your-log-bucket> --is-multi-region-trail"
                    ),
                ))
                return findings

            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if not status.get("IsLogging", False):
                        findings.append(Finding(
                            resource=trail["TrailARN"],
                            issue="CloudTrail trail exists but is NOT actively logging",
                            severity="high",
                            provider="aws",
                            resource_type="cloudtrail",
                            remediation_hint=(
                                f"aws cloudtrail start-logging --name {trail['TrailARN']}"
                            ),
                        ))
                except Exception as e:
                    logger.debug(f"Could not get trail status for {trail.get('TrailARN')}: {e}")

        except Exception as e:
            logger.warning(f"CloudTrail check failed: {e}")

        return findings

    # ── RDS ───────────────────────────────────────────────────────────────────

    def _check_rds_public(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            rds = boto3.client("rds")
            instances = rds.describe_db_instances().get("DBInstances", [])

            for db in instances:
                if db.get("PubliclyAccessible", False):
                    findings.append(Finding(
                        resource=db["DBInstanceIdentifier"],
                        issue="RDS instance is publicly accessible from the internet",
                        severity="high",
                        provider="aws",
                        resource_type="rds_instance",
                        details={
                            "engine": db.get("Engine"),
                            "endpoint": db.get("Endpoint", {}).get("Address"),
                        },
                        remediation_hint=(
                            f"aws rds modify-db-instance "
                            f"--db-instance-identifier {db['DBInstanceIdentifier']} "
                            f"--no-publicly-accessible --apply-immediately"
                        ),
                    ))

        except Exception as e:
            logger.warning(f"RDS check failed: {e}")

        return findings
