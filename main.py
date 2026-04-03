"""
Aegis — CLI entry point.

Usage:
    python main.py [--live] [--no-network]

Flags:
    --live        Disable dry-run mode (applies real remediation). Requires AUTO_REMEDIATE=true.
    --no-network  Skip network scanning even if NETWORK_SCAN_ENABLED=true.
    --providers   Comma-separated list of providers to scan: aws,azure,gcp,network
                  Default: uses .env settings.

Output:
    Prints a formatted report to stdout and saves it to report.txt.
"""

import argparse
import logging
import sys
import time
from datetime import datetime, timezone

from config import (
    AUTO_REMEDIATE,
    AWS_ENABLED,
    AZURE_ENABLED,
    AZURE_SUBSCRIPTION_ID,
    DRY_RUN,
    CLICKHOUSE_ANALYTICS_ENABLED,
    GCP_ENABLED,
    GCP_PROJECT_ID,
    NETWORK_SCAN_ENABLED,
    NETWORK_SCAN_TARGETS,
)
from modules.agents.orchestrator import AIOrchestrator
from modules.analytics.clickhouse_indexer import ClickHouseIndexer
from modules.scanners.base import Finding

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOURS = {
    "critical": "\033[91m",  # bright red
    "high":     "\033[93m",  # yellow
    "medium":   "\033[94m",  # blue
    "low":      "\033[92m",  # green
    "info":     "\033[0m",
    "reset":    "\033[0m",
}


def colour(text: str, severity: str) -> str:
    c = SEVERITY_COLOURS.get(severity.lower(), "")
    r = SEVERITY_COLOURS["reset"]
    return f"{c}{text}{r}"


def build_scanners(providers: list[str]):
    """Instantiate scanners for the requested providers."""
    from modules.scanners.aws.scanner import AWSScanner
    from modules.scanners.azure.scanner import AzureScanner
    from modules.scanners.gcp.scanner import GCPScanner
    from modules.scanners.network.scanner import NetworkScanner

    scanners = []

    if "aws" in providers and AWS_ENABLED:
        s = AWSScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("AWS scanner unavailable.")

    if "azure" in providers and AZURE_ENABLED:
        s = AzureScanner(AZURE_SUBSCRIPTION_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Azure scanner unavailable.")

    if "gcp" in providers and GCP_ENABLED:
        s = GCPScanner(GCP_PROJECT_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("GCP scanner unavailable.")

    if "network" in providers and NETWORK_SCAN_ENABLED:
        s = NetworkScanner(NETWORK_SCAN_TARGETS)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Network scanner unavailable (no targets).")

    return scanners


def format_report(remediation_results: list[dict], dry_run: bool) -> str:
    mode_label = "DRY RUN — no changes applied" if dry_run else "LIVE — changes applied"
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 60,
        "  AEGIS SECURITY REPORT",
        f"  {ts}",
        f"  Mode: {mode_label}",
        "=" * 60,
        f"  Total findings processed: {len(remediation_results)}",
        "",
    ]

    # Sort by severity
    sorted_results = sorted(
        remediation_results,
        key=lambda r: SEVERITY_ORDER.get(
            r.get("finding", {}).get("severity", "info"), 99
        ),
    )

    for item in sorted_results:
        if "error" in item and "finding" not in item:
            lines.append(f"  [ERROR] {item['error']}")
            continue

        f = item.get("finding", {})
        sev = f.get("severity", "info").upper()
        lines += [
            "",
            "-" * 60,
            f"  [{sev}] {f.get('issue', 'Unknown issue')}",
            f"  Resource : {f.get('resource')}",
            f"  Provider : {f.get('provider')}  |  Type: {f.get('resource_type')}",
        ]

        # Actions taken by agents
        actions = item.get("actions_taken", [])
        if actions:
            lines.append("  Actions taken:")
            for a in actions:
                tool = a.get("tool", "")
                result = a.get("result", {})
                status = "✓" if result.get("success") else "✗"
                lines.append(
                    f"    {status} [{tool}] {result.get('action_taken', '')} "
                    f"— {result.get('details', '')}"
                )

        # AI explanation
        explanation = item.get("explanation", {})
        if explanation.get("summary"):
            lines.append(f"\n  Risk Summary:\n    {explanation['summary']}")
        if explanation.get("manual_steps"):
            lines.append(f"\n  Manual Steps:\n    {explanation['manual_steps']}")
        if explanation.get("cli_command"):
            lines.append(f"\n  CLI Fix:\n    {explanation['cli_command']}")
        if explanation.get("terraform"):
            lines.append(f"\n  Terraform:\n    {explanation['terraform']}")

    lines += ["", "=" * 60, "  End of report", "=" * 60]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Aegis CLI scanner")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Disable dry-run and apply real remediation (requires AUTO_REMEDIATE=true in .env)",
    )
    parser.add_argument(
        "--providers",
        default="aws,azure,gcp,network",
        help="Comma-separated providers to scan (default: aws,azure,gcp,network)",
    )
    args = parser.parse_args()

    providers = [p.strip().lower() for p in args.providers.split(",")]
    dry_run = not args.live or not AUTO_REMEDIATE

    if args.live and not AUTO_REMEDIATE:
        logger.warning(
            "--live flag set but AUTO_REMEDIATE=false in .env. "
            "Running in dry-run mode. Set AUTO_REMEDIATE=true to allow live changes."
        )

    mode = "DRY RUN" if dry_run else "LIVE REMEDIATION"
    print(f"\nAegis starting | Mode: {mode} | Providers: {providers}\n")

    # Build and run scanners
    scanners = build_scanners(providers)
    if not scanners:
        print("No scanners available. Check credentials and .env configuration.")
        sys.exit(1)

    start_time = time.time()
    all_findings: list[Finding] = []
    providers_scanned: list[str] = []
    for scanner in scanners:
        print(f"  Scanning {scanner.provider.upper()}...")
        try:
            findings = scanner.scan()
            print(f"    → {len(findings)} finding(s)")
            all_findings.extend(findings)
            if findings:
                providers_scanned.append(scanner.provider)
        except Exception as e:
            logger.error(f"Scanner {scanner.provider} failed: {e}")

    if not all_findings:
        print("\nNo security issues found.")
        return

    print(f"\n  Total findings: {len(all_findings)}  — running AI orchestrator...\n")

    # Run AI orchestrator
    orchestrator = AIOrchestrator(dry_run=dry_run, auto_remediate=AUTO_REMEDIATE)
    results = orchestrator.process_findings(all_findings)
    duration = time.time() - start_time

    # Format and output report
    report = format_report(results, dry_run)
    print(report)

    report_path = "report.txt"
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\nReport saved to {report_path}")

    # ── Ship to ClickHouse ────────────────────────────────────────────────────
    if CLICKHOUSE_ANALYTICS_ENABLED:
        import uuid as _uuid
        scan_id = str(_uuid.uuid4())
        indexer = ClickHouseIndexer()
        if indexer.is_available():
            by_sev: dict = {}
            for f in all_findings:
                by_sev.setdefault(f.severity, 0)
                by_sev[f.severity] += 1
            summary = {
                "total":    len(all_findings),
                "critical": by_sev.get("critical", 0),
                "high":     by_sev.get("high", 0),
                "medium":   by_sev.get("medium", 0),
                "low":      by_sev.get("low", 0),
            }
            indexed = indexer.bulk_index_scan_results(
                scan_id=scan_id,
                remediation_results=results,
                summary=summary,
                providers_scanned=providers_scanned,
                dry_run=dry_run,
                auto_remediate=AUTO_REMEDIATE,
                duration_seconds=duration,
            )
            print(
                f"\nClickHouse: indexed {indexed['findings']} findings, "
                f"{indexed['remediations']} remediations → view in dashboard"
            )
        else:
            print("\nClickHouse analytics enabled but unreachable — results not indexed.")


if __name__ == "__main__":
    main()
