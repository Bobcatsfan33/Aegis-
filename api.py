"""
Aegis — FastAPI web service  (v2.6.0)

Endpoints:
  GET  /                   → health check (public)
  POST /scan               → start async scan + remediation (ANALYST+)
  GET  /scan/{scan_id}     → poll scan status / retrieve results (ANALYST+)
  GET  /scans              → list all scan IDs and their status (ANALYST+)
  GET  /api/findings       → paginated findings query (ANALYST+)
  GET  /api/compliance     → NIST 800-53 Rev5 compliance gap report (ANALYST+)
  GET  /api/stig           → DISA STIG automated assessment (ANALYST+)
  GET  /api/stig/xccdf     → XCCDF 1.2 XML export for eMASS import (ADMIN+)
  GET  /api/stig/poam      → eMASS POA&M CSV template (ADMIN+)
  GET  /api/acas           → ACAS/Nessus vulnerability scan summary (ANALYST+)
  GET  /api/acas/findings  → paginated ACAS findings (ANALYST+)
  POST /api/acas/scan      → trigger on-demand ACAS pull from Tenable.sc/Nessus (ADMIN+)
  GET  /api/audit          → tail the immutable audit log (OWNER only)

v2.7.0 — mTLS Service Mesh:
  - MTLSMiddleware: proxy mode (Nginx/Envoy) and native mode (Uvicorn TLS).
  - Inbound API plane: client cert enforcement for operator tooling and SIEM agents.
  - Outbound scanner plane: OutboundMTLSSession / AsyncOutboundMTLSSession
    for Tenable.sc, DoD SIEM, and eMASS REST API mTLS connections.
  - FIPS-approved cipher suite (TLS 1.2+, ECDHE-AES-GCM).
  - CN allowlist (MTLS_ALLOWED_CNS) with SAN fallback.
  - AEGIS_CLIENT_CERT / AEGIS_CLIENT_KEY for scanner outbound identity.
  - NIST SC-8, SC-8(1), IA-3, SC-17, MA-3, RA-5, SI-7 coverage.

v2.6.0 — Version alignment with TokenDNA Attribution Dashboard release.

v2.5.0 — Active Defense + ACAS Integration:
  - ACAS/Nessus scanner integration (Tenable.sc API, Nessus API, .nessus XML).
  - CVSS v3/v2 severity normalization, IAVM notice ID extraction.
  - Plugin-family → NIST 800-53 Rev5 + MITRE ATT&CK mapping.
  - eMASS POA&M candidates auto-generated from critical/high ACAS findings.
  - ACAS findings fed into existing compliance gap report.

v2.4.0 — IL5 Foundation:
  - FIPS 140-2 startup enforcement (FATAL in IL5/IL6 if not FIPS-active).
  - DISA ASD STIG V5R3 + Container SRG V1R3 automated checker (19 checks).
  - XCCDF 1.2 export for eMASS SAR import.
  - eMASS-compatible POA&M CSV generator.
  - DPoP (RFC 9449) module available in TokenDNA; wired for token binding.
  - HVIP enforcer for OWNER/ADMIN identity hardening profiles.

v2.3.0:
  - Kubernetes CIS Benchmark scanner (K8S_ENABLED).
  - IaC shift-left scanner for Terraform/CloudFormation/K8s manifests (IAC_ENABLED).
  - NIST 800-53 Rev5 compliance report generator.

v2.2.0:
  - SecurityHeadersMiddleware + RequestValidationMiddleware applied globally.
  - CORS wildcard replaced with CORS_ORIGINS env var.
  - RBAC on all mutating / data endpoints.
  - Immutable hash-chained audit log.
"""

import logging
import os
import time
import uuid
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from auth import verify_token
from config import (
    AUTO_REMEDIATE,
    AWS_ENABLED,
    AZURE_ENABLED,
    AZURE_SUBSCRIPTION_ID,
    DEV_MODE,
    DRY_RUN,
    ELASTICSEARCH_ENABLED,
    GCP_ENABLED,
    GCP_PROJECT_ID,
    IAC_ENABLED,
    K8S_ENABLED,
    NETWORK_SCAN_ENABLED,
    NETWORK_SCAN_TARGETS,
    OIDC_ISSUER,
)
from modules.agents.orchestrator import AIOrchestrator
from modules.analytics.elastic import ElasticIndexer
from modules.compliance.stig import STIGChecker, STIGStatus
from modules.reports.compliance import ComplianceReportGenerator
from modules.scanners.base import Finding
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event
from modules.security.fips import fips as _fips
from modules.security.headers import RequestValidationMiddleware, SecurityHeadersMiddleware
from modules.security.rbac import Role, require_role
from modules.transport.mtls import (
    MTLSMiddleware as _MTLSMiddleware,
    check_mtls_config as _check_mtls_config,
    OutboundMTLSSession,
)

logger = logging.getLogger(__name__)

# ── App ────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Aegis",
    description="Autonomous multi-cloud & network security posture management",
    version="2.7.0",
    # Suppress /openapi.json and /docs in non-dev environments (reduces attack surface)
    docs_url="/docs" if DEV_MODE else None,
    redoc_url="/redoc" if DEV_MODE else None,
)

# ── STIG checker singleton ─────────────────────────────────────────────────────
_stig_checker = STIGChecker()

# ── Middleware stack (order matters: outermost = last added, executes first) ───
# Execution order: CORS → mTLS → RequestValidation → SecurityHeaders → routes

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)
# SC-8 / IA-3: mTLS inbound API enforcement (operator tooling + SIEM push agents)
if os.getenv("MTLS_MODE", "").lower() in ("proxy", "native"):
    app.add_middleware(_MTLSMiddleware)
    logger.info("Aegis mTLS middleware ENABLED (mode=%s)", os.getenv("MTLS_MODE"))

_cors_origins: list[str] = [
    o.strip()
    for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
    if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-API-Key", "X-Correlation-ID", "Content-Type",
                   "X-Client-Cert", "X-Forwarded-Client-Cert"],
    allow_credentials=False,
)

# ── In-memory scan store — replace with Redis for multi-replica deployments ───

scan_results: dict[str, Any] = {}

# ── Analytics indexer ─────────────────────────────────────────────────────────

_indexer = ElasticIndexer()


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_checks():
    # SC-13 / IA-7: FIPS 140-2 enforcement — FATAL in IL5/IL6 if FIPS not active
    _fips.startup_check()
    fips_summary = _fips.compliance_summary()
    if fips_summary.get("fips_active"):
        logger.info("FIPS 140-2: ACTIVE — all cryptographic operations use validated modules.")
    else:
        logger.warning(
            f"FIPS 140-2: NOT ACTIVE (environment={fips_summary.get('environment')}). "
            "Enable kernel FIPS mode before deploying to IL4/IL5/IL6."
        )

    if not OIDC_ISSUER:
        logger.warning(
            "OIDC_ISSUER is not set. All authenticated endpoints will return 401. "
            "Set OIDC_ISSUER in your .env file."
        )

    mode = "DRY RUN" if DRY_RUN else "LIVE REMEDIATION"
    logger.info(f"Aegis v2.7.0 starting in {mode} mode.")

    acas_mode = os.getenv("ACAS_MODE", "xml")
    logger.info("ACAS scanner mode: %s (RA-5 / SI-2)", acas_mode)

    # v2.7: mTLS config validation (SC-8, IA-3)
    mtls_mode = os.getenv("MTLS_MODE", "").lower()
    mtls_summary: dict = {}
    if mtls_mode in ("proxy", "native"):
        try:
            mtls_summary = _check_mtls_config()
        except Exception as exc:
            logger.error("Aegis mTLS config error: %s", exc)
    else:
        logger.warning(
            "Aegis mTLS: NOT ENABLED (MTLS_MODE not set). "
            "Set MTLS_MODE=proxy|native for IL4/IL5 inter-service transport (SC-8)."
        )

    if ELASTICSEARCH_ENABLED:
        if _indexer.is_available():
            _indexer.ensure_indices()
            logger.info("Elasticsearch connected — findings will be indexed.")
        else:
            logger.warning(
                "ELASTICSEARCH_ENABLED=true but connection failed. "
                "Check ELASTICSEARCH_URL and credentials."
            )

    # AU-2 / AU-12: emit auditable startup event
    log_event(
        AuditEventType.STARTUP,
        AuditOutcome.SUCCESS,
        detail={
            "version": "2.7.0",
            "dev_mode": DEV_MODE,
            "dry_run": DRY_RUN,
            "auto_remediate": AUTO_REMEDIATE,
            "fips_active": fips_summary.get("fips_active", False),
            "fips_environment": fips_summary.get("environment", "unknown"),
            "acas_mode": os.getenv("ACAS_MODE", "xml"),
            "mtls_mode": mtls_mode or "disabled",
            "mtls_inbound_certs": mtls_summary.get("inbound_certs_present", False),
            "mtls_outbound_certs": mtls_summary.get("outbound_certs_present", False),
        },
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

    if K8S_ENABLED:
        from modules.scanners.k8s.scanner import K8sScanner
        s = K8sScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("K8s scanner unavailable (check kubeconfig / cluster connectivity).")

    if IAC_ENABLED:
        from modules.scanners.iac.scanner import IaCScanner
        s = IaCScanner()
        if s.is_available():
            scanners.append(s)
        else:
            logger.warning("IaC scanner: no scan paths found. Set IAC_SCAN_PATHS.")

    # ACAS / Nessus scanner (always attempted when ACAS_MODE is set)
    # ACAS_MODE = "tenablesc" | "nessus" | "xml" (default: xml / disabled if no path set)
    if os.getenv("ACAS_MODE") or os.getenv("NESSUS_XML_PATH"):
        from modules.scanners.acas.scanner import ACASScanner
        s = ACASScanner()
        if s.is_available():
            scanners.append(s)
            logger.info("ACAS scanner enabled (mode=%s)", os.getenv("ACAS_MODE", "xml"))
        else:
            logger.warning(
                "ACAS scanner unavailable — check ACAS_MODE, TENABLESC_URL / "
                "NESSUS_URL / NESSUS_XML_PATH in .env"
            )

    return scanners


def _summarize(findings: list[Finding]) -> dict:
    by_severity: dict[str, list] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f.to_dict())
    return {
        "total":    len(findings),
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

def _run_scan(scan_id: str, initiated_by: str):
    scan_results[scan_id]["status"] = "running"
    start_time = time.time()
    try:
        scanners = _build_scanners()
        if not scanners:
            scan_results[scan_id] = {
                "status": "error",
                "error": "No scanners available. Check credentials and provider settings.",
            }
            log_event(
                AuditEventType.SCAN_COMPLETE,
                AuditOutcome.FAILURE,
                actor=initiated_by,
                detail={"scan_id": scan_id, "error": "no_scanners_available"},
            )
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
        logger.info(
            f"Scan {scan_id} complete: {len(all_findings)} findings in {duration:.1f}s."
        )

        # AU-2: audit successful scan completion
        log_event(
            AuditEventType.SCAN_COMPLETE,
            AuditOutcome.SUCCESS,
            actor=initiated_by,
            detail={
                "scan_id": scan_id,
                "total_findings": len(all_findings),
                "critical": summary["critical"],
                "high": summary["high"],
                "providers": providers_scanned,
                "duration_seconds": round(duration, 2),
            },
        )

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
        log_event(
            AuditEventType.SCAN_COMPLETE,
            AuditOutcome.FAILURE,
            actor=initiated_by,
            detail={"scan_id": scan_id, "error": str(e)},
        )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    """Public health check — no auth required."""
    fips_info = _fips.compliance_summary()
    return {
        "service":        "Aegis",
        "version":        "2.7.0",
        "status":         "running",
        "mode":           "dry_run" if DRY_RUN else "live",
        "auto_remediate": AUTO_REMEDIATE,
        "fips_active":    fips_info.get("fips_active", False),
        "il_environment": fips_info.get("environment", "unknown"),
        "mtls_enabled":   os.getenv("MTLS_MODE", "").lower() in ("proxy", "native"),
        "mtls_mode":      os.getenv("MTLS_MODE", "disabled"),
    }


@app.post("/scan", status_code=202)
def start_scan(
    background_tasks: BackgroundTasks,
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Start a full multi-cloud + network scan.
    Requires ANALYST role or higher.
    Returns immediately with scan_id; poll GET /scan/{scan_id} for results.
    """
    scan_id = str(uuid.uuid4())
    actor = tenant.get("sub", "unknown")
    scan_results[scan_id] = {"status": "queued"}
    background_tasks.add_task(_run_scan, scan_id, actor)

    log_event(
        AuditEventType.SCAN_STARTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"scan_id": scan_id},
    )
    logger.info(f"Scan {scan_id} queued by {actor}.")
    return {"message": "Scan started", "scan_id": scan_id}


@app.get("/scan/{scan_id}")
def get_scan(
    scan_id: str,
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """Retrieve status and results for a specific scan. Requires ANALYST+."""
    result = scan_results.get(scan_id)
    if result is None:
        log_event(
            AuditEventType.ACCESS_DENIED,
            AuditOutcome.FAILURE,
            actor=tenant.get("sub", "unknown"),
            detail={"scan_id": scan_id, "reason": "not_found"},
        )
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=tenant.get("sub", "unknown"),
        detail={"scan_id": scan_id, "status": result.get("status")},
    )
    return result


@app.get("/scans")
def list_scans(tenant: dict = Depends(require_role(Role.ANALYST))):
    """List all scans in memory with their status. Requires ANALYST+."""
    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=tenant.get("sub", "unknown"),
        detail={"action": "list_scans", "count": len(scan_results)},
    )
    return {
        scan_id: {
            "status": data.get("status"),
            "total":  data.get("summary", {}).get("total"),
        }
        for scan_id, data in scan_results.items()
    }


# ── Dashboard API endpoints ───────────────────────────────────────────────────

@app.get("/api/findings")
def get_findings(
    severity: str | None = Query(None, description="Filter by severity: critical|high|medium|low"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Return paginated findings from in-memory scan results (or Elasticsearch if enabled).
    Requires ANALYST+.
    """
    actor = tenant.get("sub", "unknown")
    all_findings_raw: list[dict] = []

    # Collect from completed scans
    for scan_id, data in scan_results.items():
        if data.get("status") != "complete":
            continue
        for item in data.get("findings", []):
            f = item.get("finding", item)
            if severity and f.get("severity") != severity:
                continue
            all_findings_raw.append({**f, "scan_id": scan_id})

    total = len(all_findings_raw)
    page = all_findings_raw[offset: offset + limit]

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"action": "get_findings", "total": total, "severity_filter": severity},
    )
    return {"total": total, "offset": offset, "limit": limit, "findings": page}


@app.get("/api/compliance")
def get_compliance_report(
    format: str = Query("json", description="Output format: json | markdown"),
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Generate a NIST 800-53 Rev5 compliance gap report from all completed scans.
    Requires ANALYST+. OWNER receives full finding details; ANALYST receives summary.
    CM-6 / CA-7: Continuous monitoring and compliance assessment.
    """
    actor = tenant.get("sub", "unknown")
    actor_role = tenant.get("role", 0)

    # Collect all findings from completed scans
    all_findings: list[Finding] = []
    for scan_id, data in scan_results.items():
        if data.get("status") != "complete":
            continue
        for item in data.get("findings", []):
            f_data = item.get("finding", item)
            # Re-hydrate Finding objects for the compliance engine
            all_findings.append(Finding(
                resource=f_data.get("resource", ""),
                issue=f_data.get("issue", ""),
                severity=f_data.get("severity", "info"),
                provider=f_data.get("provider", "unknown"),
                region=f_data.get("region"),
                resource_type=f_data.get("resource_type"),
                details=f_data.get("details", {}),
                remediation_hint=f_data.get("remediation_hint"),
                mitre_techniques=f_data.get("mitre_techniques", []),
                mitre_tactic=f_data.get("mitre_tactic"),
                nist_controls=f_data.get("nist_controls", []),
                cwe_id=f_data.get("cwe_id"),
            ))

    generator = ComplianceReportGenerator()
    report = generator.generate(
        all_findings,
        metadata={"scan_count": len(scan_results), "actor": actor},
    )

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={
            "action": "compliance_report",
            "overall_score": report.overall_score,
            "total_findings": report.total_findings,
        },
    )

    if format == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(report.to_markdown(), media_type="text/markdown")

    return report.to_dict()


@app.get("/api/stig")
def get_stig_report(
    format: str = Query("json", description="Output format: json | markdown"),
    cat_i_only: bool = Query(False, description="Run only CAT I (critical) checks for speed"),
    tenant: dict = Depends(require_role(Role.ANALYST)),
):
    """
    Run automated DISA STIG checks and return results.
    Covers ASD STIG V5R3 (14 checks) + Container Platform SRG V1R3 (5 checks).
    Requires ANALYST+.

    CA-2 / CA-7: Security assessment and continuous monitoring.
    RA-5: Vulnerability scanning mapped to STIG VulnIDs.
    """
    actor = tenant.get("sub", "unknown")

    report = (
        _stig_checker.run_cat_i_only()
        if cat_i_only
        else _stig_checker.run_all()
    )
    summary = report.summary()

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={
            "action": "stig_assessment",
            "cat_i_open": summary["cat_i"],
            "cat_ii_open": summary["cat_ii"],
            "cat_iii_open": summary["cat_iii"],
            "total_checks": summary["total"],
        },
    )

    if format == "markdown":
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(report.to_markdown(), media_type="text/markdown")

    return report.to_dict()


@app.get("/api/stig/xccdf")
def get_stig_xccdf(
    tenant: dict = Depends(require_role(Role.ADMIN)),
):
    """
    Export STIG results as XCCDF 1.2 XML for eMASS SAR import.
    Requires ADMIN role — XCCDF exports are sensitive compliance artifacts.

    CA-2: Security assessment — XCCDF is the eMASS-accepted format for SAR evidence.
    """
    from fastapi.responses import Response

    actor = tenant.get("sub", "unknown")
    report = _stig_checker.run_all()

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"action": "stig_xccdf_export", "open_cat_i": report.summary()["cat_i"]},
    )

    xml_content = report.to_xccdf_xml()
    filename = f"aegis-stig-{report.scan_time[:10]}.xml"
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/stig/poam")
def get_stig_poam(
    tenant: dict = Depends(require_role(Role.ADMIN)),
):
    """
    Generate eMASS-compatible POA&M CSV template from open STIG findings.
    Requires ADMIN role.

    CA-5: Plan of Action & Milestones — eMASS POA&M import format v9.3.
    """
    from fastapi.responses import Response

    actor = tenant.get("sub", "unknown")
    report = _stig_checker.run_all()
    summary = report.summary()

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={
            "action": "stig_poam_export",
            "open_findings": summary["open"],
            "cat_i": summary["cat_i"],
        },
    )

    csv_content = report.to_poam_csv()
    filename = f"aegis-poam-{report.scan_time[:10]}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/audit")
def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    tenant: dict = Depends(require_role(Role.OWNER)),
):
    """
    Return the tail of the immutable audit log.
    Requires OWNER role — guards against audit log exfiltration by lower-privilege actors.
    AU-9: Protection of audit information.
    """
    import json
    audit_path = os.getenv("AUDIT_LOG_FILE", "audit.jsonl")
    actor = tenant.get("sub", "unknown")

    log_event(
        AuditEventType.ACCESS_GRANTED,
        AuditOutcome.SUCCESS,
        actor=actor,
        detail={"action": "read_audit_log", "requested_limit": limit},
    )

    if not os.path.exists(audit_path):
        return {"entries": [], "total": 0}

    entries: list[dict] = []
    try:
        with open(audit_path, "r") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not read audit log: {exc}")

    tail = entries[-limit:]
    return {"entries": tail, "total": len(entries)}


# ── ACAS / Nessus Endpoints ────────────────────────────────────────────────────
# RA-5 (Vulnerability Scanning), SI-2 (Flaw Remediation), CM-6 (Configuration)
# All endpoints require ANALYST+ — ACAS findings are sensitive vulnerability data.

# In-memory cache of last ACAS scan results (replace with Redis for multi-replica)
_acas_cache: dict[str, Any] = {
    "findings": [],
    "summary":  None,
    "scan_id":  None,
    "scanned_at": None,
}


@app.get("/api/acas")
async def acas_summary(
    _user: dict = Depends(verify_token),
    _role: Any = Depends(require_role(Role.ANALYST)),
):
    """
    Return ACAS/Nessus vulnerability scan summary.

    Summary includes:
      - Severity counts (critical / high / medium / low)
      - Unique host count and unique CVE count
      - Open IAVM notice IDs (DoD IA Vulnerability Management)
      - Top 10 most frequent plugins
      - Top 10 most vulnerable hosts
      - POA&M candidates (critical + high + IAVM findings for eMASS)

    ACAS data is sourced from the most recent scan run (GET /api/acas/scan)
    or from the background scan (POST /scan) when ACAS_MODE is configured.
    RA-5 / SI-2 / CM-6.
    """
    from modules.scanners.acas.scanner import ACASScanner, build_summary

    if not _acas_cache["summary"]:
        # No cached results — attempt a fresh pull if scanner is available
        scanner = ACASScanner()
        if not scanner.is_available():
            return {
                "status": "unavailable",
                "message": (
                    "ACAS scanner not configured. Set ACAS_MODE + credentials "
                    "or NESSUS_XML_PATH in .env to enable vulnerability scanning."
                ),
            }
        findings = scanner.scan()
        _acas_cache["findings"] = [f.to_dict() for f in findings]
        _acas_cache["summary"]  = build_summary(findings).to_dict()
        _acas_cache["scanned_at"] = _acas_cache["summary"]["generated_at"]

    return {
        "scan_id":    _acas_cache["scan_id"],
        "scanned_at": _acas_cache["scanned_at"],
        "summary":    _acas_cache["summary"],
    }


@app.get("/api/acas/findings")
async def acas_findings(
    severity: str = Query(default="", description="Filter by severity (critical|high|medium|low)"),
    host: str     = Query(default="", description="Filter by hostname or IP (partial match)"),
    cve: str      = Query(default="", description="Filter by CVE ID (partial match)"),
    limit: int    = Query(default=100, le=1000),
    offset: int   = Query(default=0, ge=0),
    _user: dict   = Depends(verify_token),
    _role: Any    = Depends(require_role(Role.ANALYST)),
):
    """
    Return paginated ACAS/Nessus finding details with optional filters.

    Each finding includes: resource, issue, severity, CVSS scores, CVE list,
    IAVM IDs, plugin family, NIST 800-53 controls, MITRE ATT&CK techniques,
    and remediation guidance.
    """
    from modules.scanners.acas.scanner import ACASScanner, build_summary

    if not _acas_cache["findings"]:
        scanner = ACASScanner()
        if not scanner.is_available():
            return {"findings": [], "total": 0, "offset": offset, "limit": limit}
        findings = scanner.scan()
        _acas_cache["findings"] = [f.to_dict() for f in findings]
        _acas_cache["summary"]  = build_summary(findings).to_dict()
        _acas_cache["scanned_at"] = _acas_cache["summary"]["generated_at"]

    all_f = _acas_cache["findings"]

    # Apply filters
    if severity:
        all_f = [f for f in all_f if f.get("severity", "").lower() == severity.lower()]
    if host:
        host_lower = host.lower()
        all_f = [
            f for f in all_f
            if host_lower in (f.get("details", {}).get("hostname", "") or "").lower()
            or host_lower in (f.get("details", {}).get("ip", "") or "").lower()
        ]
    if cve:
        cve_lower = cve.lower()
        all_f = [
            f for f in all_f
            if any(cve_lower in c.lower() for c in f.get("details", {}).get("cves", []))
        ]

    total = len(all_f)
    page  = all_f[offset: offset + limit]

    return {
        "findings": page,
        "total":    total,
        "offset":   offset,
        "limit":    limit,
        "filtered_by": {
            "severity": severity or None,
            "host":     host or None,
            "cve":      cve or None,
        },
    }


@app.post("/api/acas/scan", status_code=202)
async def acas_trigger_scan(
    background_tasks: BackgroundTasks,
    _user: dict = Depends(verify_token),
    _role: Any  = Depends(require_role(Role.ADMIN)),
):
    """
    Trigger an on-demand ACAS/Nessus pull from the configured source.

    Runs in the background; poll GET /api/acas for updated results.
    ADMIN+ required — triggers external API calls to Tenable.sc / Nessus.
    RA-5 / CM-6.
    """
    from modules.scanners.acas.scanner import ACASScanner, build_summary

    actor = _user.get("sub", "unknown")

    def _run_acas():
        scanner = ACASScanner()
        if not scanner.is_available():
            logger.warning("[ACAS] Scan triggered by %s but scanner unavailable", actor)
            return
        logger.info("[ACAS] On-demand scan triggered by %s", actor)
        findings = scanner.scan()
        summary  = build_summary(findings)
        _acas_cache["findings"]   = [f.to_dict() for f in findings]
        _acas_cache["summary"]    = summary.to_dict()
        _acas_cache["scanned_at"] = summary.generated_at
        logger.info(
            "[ACAS] On-demand scan complete: %d findings (%d critical, %d high)",
            summary.total_findings, summary.critical, summary.high,
        )
        log_event(
            AuditEventType.STARTUP,       # reuse closest available type
            AuditOutcome.SUCCESS,
            detail={
                "action":        "acas_scan",
                "triggered_by":  actor,
                "total":         summary.total_findings,
                "critical":      summary.critical,
                "high":          summary.high,
                "iavm_open":     summary.iavm_open,
            },
        )

    background_tasks.add_task(_run_acas)

    return {
        "status":  "queued",
        "message": "ACAS scan started. Poll GET /api/acas for results.",
        "actor":   actor,
    }
