"""
Aegis — FastAPI web service.

Endpoints:
  GET  /              → health check
  POST /scan          → start an async scan + remediation run (requires auth)
  GET  /scan/{scan_id}→ poll scan status / retrieve results (requires auth)
  GET  /scans         → list all scan IDs and their status (requires auth)

Changes vs. original:
  - scan_id uses uuid4 (thread-safe, collision-free).
  - scan_results tracks status ("running" | "complete" | "error").
  - summarize() lives here only (removed duplication with main.py).
  - All scanner/orchestrator wiring uses the new multi-cloud architecture.
  - OIDC_ISSUER misconfiguration gives a clear startup warning instead of crashing.
"""

import logging
import time
import uuid
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException

from auth import verify_token
from config import (
    AUTO_REMEDIATE,
    AWS_ENABLED,
    AZURE_ENABLED,
    AZURE_SUBSCRIPTION_ID,
    DRY_RUN,
    ELASTICSEARCH_ENABLED,
    GCP_ENABLED,
    GCP_PROJECT_ID,
    NETWORK_SCAN_ENABLED,
    NETWORK_SCAN_TARGETS,
    OIDC_ISSUER,
)
from modules.agents.orchestrator import AIOrchestrator
from modules.analytics.elastic import ElasticIndexer
from modules.scanners.base import Finding

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Aegis",
    description="Autonomous multi-cloud & network security posture management",
    version="2.0.0",
)

# In-memory store — replace with Redis / a DB for production persistence
scan_results: dict[str, Any] = {}


# ── Startup warning ───────────────────────────────────────────────────────────

_indexer = ElasticIndexer()


@app.on_event("startup")
async def startup_checks():
    if not OIDC_ISSUER:
        logger.warning(
            "OIDC_ISSUER is not set. All authenticated endpoints will return 401. "
            "Set OIDC_ISSUER in your .env file."
        )
    mode = "DRY RUN" if DRY_RUN else "LIVE REMEDIATION"
    logger.info(f"Aegis starting in {mode} mode.")

    if ELASTICSEARCH_ENABLED:
        if _indexer.is_available():
            _indexer.ensure_indices()
            logger.info("Elasticsearch connected — findings will be indexed.")
        else:
            logger.warning(
                "ELASTICSEARCH_ENABLED=true but connection failed. "
                "Check ELASTICSEARCH_URL and credentials."
            )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_scanners():
    """Instantiate whichever scanners are enabled and have available credentials."""
    from modules.scanners.aws.scanner import AWSScanner
    from modules.scanners.azure.scanner import AzureScanner
    from modules.scanners.gcp.scanner import GCPScanner
    from modules.scanners.network.scanner import NetworkScanner

    scanners = []

    if AWS_ENABLED:
        s = AWSScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("AWS scanner unavailable (missing credentials or boto3).")

    if AZURE_ENABLED:
        s = AzureScanner(AZURE_SUBSCRIPTION_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Azure scanner unavailable (missing credentials or SDK).")

    if GCP_ENABLED:
        s = GCPScanner(GCP_PROJECT_ID)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("GCP scanner unavailable (missing credentials or SDK).")

    if NETWORK_SCAN_ENABLED:
        s = NetworkScanner(NETWORK_SCAN_TARGETS)
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("Network scanner has no targets configured.")

    return scanners


def _summarize(findings: list[Finding]) -> dict:
    by_severity = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f.to_dict())
    return {
        "total": len(findings),
        "critical": len(by_severity.get("critical", [])),
        "high":     len(by_severity.get("high", [])),
        "medium":   len(by_severity.get("medium", [])),
        "low":      len(by_severity.get("low", [])),
        "top_risks": [
            f.to_dict()
            for f in findings
            if f.severity in ("critical", "high")
        ][:5],
    }


# ── Background task ───────────────────────────────────────────────────────────

def _run_scan(scan_id: str):
    scan_results[scan_id]["status"] = "running"
    start_time = time.time()
    try:
        scanners = _build_scanners()
        if not scanners:
            scan_results[scan_id] = {
                "status": "error",
                "error": "No scanners available. Check credentials and provider settings.",
            }
            return

        all_findings: list[Finding] = []
        providers_scanned: list[str] = []
        for scanner in scanners:
            try:
                results = scanner.scan()
                all_findings.extend(results)
                if results:
                    providers_scanned.append(scanner.provider)
            except Exception as e:
                logger.error(f"Scanner {scanner.provider} failed: {e}")

        orchestrator = AIOrchestrator(dry_run=DRY_RUN, auto_remediate=AUTO_REMEDIATE)
        remediation_results = orchestrator.process_findings(all_findings)

        summary = _summarize(all_findings)
        duration = time.time() - start_time

        scan_results[scan_id] = {
            "status":   "complete",
            "summary":  summary,
            "findings": remediation_results,
        }
        logger.info(f"Scan {scan_id} complete: {len(all_findings)} findings in {duration:.1f}s.")

        # ── Ship to Elasticsearch / Kibana ──────────────────────────────────
        if ELASTICSEARCH_ENABLED and _indexer.is_available():
            indexed = _indexer.bulk_index_scan_results(
                scan_id=scan_id,
                remediation_results=remediation_results,
                summary=summary,
                providers_scanned=providers_scanned,
                dry_run=DRY_RUN,
                auto_remediate=AUTO_REMEDIATE,
                duration_seconds=duration,
            )
            logger.info(
                f"Elasticsearch: indexed {indexed['findings']} findings, "
                f"{indexed['remediations']} remediations, "
                f"{indexed['scans']} scan summary."
            )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed with unhandled exception: {e}")
        scan_results[scan_id] = {"status": "error", "error": str(e)}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "Aegis",
        "status": "running",
        "mode": "dry_run" if DRY_RUN else "live",
        "auto_remediate": AUTO_REMEDIATE,
    }


@app.post("/scan")
def start_scan(
    background_tasks: BackgroundTasks,
    user: dict = Depends(verify_token),
):
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {"status": "queued"}
    background_tasks.add_task(_run_scan, scan_id)
    logger.info(f"Scan {scan_id} queued by {user.get('sub', 'unknown')}.")
    return {"message": "Scan started", "scan_id": scan_id}


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str, user: dict = Depends(verify_token)):
    result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return result


@app.get("/scans")
def list_scans(user: dict = Depends(verify_token)):
    return {
        scan_id: {"status": data.get("status"), "total": data.get("summary", {}).get("total")}
        for scan_id, data in scan_results.items()
    }
