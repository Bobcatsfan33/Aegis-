"""
Aegis — Continuous Monitoring (ConMon) Automation  (v2.10.0)
=============================================================
Automated ConMon pipeline that satisfies DISA DAAPM v2.2 Section 3.4
(Continuous Monitoring Strategy) and NIST SP 800-137 requirements.

Pipeline Stages
---------------
1. SCAN    — Trigger all enabled Aegis scanners (cloud, K8s, IaC, ACAS)
2. ASSESS  — Run STIG automated checks + compliance gap report
3. REPORT  — Generate eMASS-formatted monthly status report + POA&M delta
4. PUSH    — POST updated controls + POA&M to eMASS REST API (optional)
5. ALERT   — Send summary to SIEM webhook and Slack

Schedule
--------
- Monthly scan  (NIST CA-7 monthly frequency for IL5)
- Weekly STIG   (DISA recommendation for automated checks)
- Daily ACAS    (RA-5 continuous scanning)
- On-demand     (POST /api/conmon/run — ADMIN+)

NIST 800-53 Rev5 Controls
--------------------------
  CA-7    Continuous Monitoring
  CA-7(1) Independent Assessment
  CA-2    Control Assessments
  CA-5    Plan of Action and Milestones (POA&M update)
  RA-5    Vulnerability Monitoring and Scanning
  SI-4    System Monitoring
  AU-6    Audit Record Review, Analysis, and Reporting

DISA References
---------------
  DAAPM v2.2 Section 3.4 — Continuous Monitoring Strategy
  NIST SP 800-137 — Information Security Continuous Monitoring (ISCM)
  eMASS User Guide v9.x — POA&M Management

eMASS REST API
--------------
Aegis uses the eMASS REST API to:
  - GET /api/v3/systems/{id}/controls       → pull current control status
  - PUT /api/v3/systems/{id}/controls       → push updated control status
  - POST /api/v3/systems/{id}/poams         → add new POA&M items
  - PUT /api/v3/systems/{id}/poams/{poamId} → update existing POA&M items
  - POST /api/v3/systems/{id}/artifacts     → upload monthly report artifact

Configuration
-------------
  EMASS_URL          https://emass.yourdomain.mil   (eMASS base URL)
  EMASS_API_KEY      <api-key>                      (eMASS API key)
  EMASS_SYSTEM_ID    <int>                          (eMASS system ID)
  EMASS_USER_UID     <int>                          (eMASS user UID for POA&M)
  CONMON_SIEM_URL    https://siem.yourdomain.mil/ingest
  CONMON_SLACK_URL   https://hooks.slack.com/services/...
  CONMON_DRY_RUN     true                           (don't push to eMASS)
"""

from __future__ import annotations

import io
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

EMASS_URL        = os.getenv("EMASS_URL",        "")
EMASS_API_KEY    = os.getenv("EMASS_API_KEY",    "")
EMASS_SYSTEM_ID  = int(os.getenv("EMASS_SYSTEM_ID", "0"))
EMASS_USER_UID   = int(os.getenv("EMASS_USER_UID", "0"))
CONMON_SIEM_URL  = os.getenv("CONMON_SIEM_URL",  "")
CONMON_SLACK_URL = os.getenv("CONMON_SLACK_URL", "")
CONMON_DRY_RUN   = os.getenv("CONMON_DRY_RUN",  "true").lower() == "true"


# ── ConMon run result ──────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    provider:     str
    total:        int
    critical:     int
    high:         int
    medium:       int
    low:          int
    new_findings: int    # delta since last run
    iavm_open:    int    = 0


@dataclass
class STIGResult:
    total_checks:   int
    passed:         int
    failed:         int
    not_applicable: int
    open_cat1:      int  # CAT I = critical
    open_cat2:      int  # CAT II = high
    open_cat3:      int  # CAT III = medium


@dataclass
class POAMDelta:
    added:   int
    closed:  int
    updated: int
    overdue: int


@dataclass
class eMASSSyncResult:
    controls_updated: int
    poams_added:      int
    poams_updated:    int
    artifact_id:      Optional[str] = None
    error:            Optional[str] = None


@dataclass
class ConMonRunResult:
    """Complete result of a ConMon pipeline run."""
    run_id:         str
    started_at:     str
    completed_at:   str
    stage:          str   # completed stage or "FAILED"
    scan_results:   list[ScanResult]   = field(default_factory=list)
    stig_result:    Optional[STIGResult] = None
    poam_delta:     Optional[POAMDelta]  = None
    emass_sync:     Optional[eMASSSyncResult] = None
    alerts_sent:    int   = 0
    error:          Optional[str] = None
    dry_run:        bool  = CONMON_DRY_RUN

    @property
    def total_critical(self) -> int:
        return sum(r.critical for r in self.scan_results)

    @property
    def total_high(self) -> int:
        return sum(r.high for r in self.scan_results)

    @property
    def total_findings(self) -> int:
        return sum(r.total for r in self.scan_results)

    def to_summary(self) -> dict[str, Any]:
        return {
            "run_id":          self.run_id,
            "started_at":      self.started_at,
            "completed_at":    self.completed_at,
            "stage":           self.stage,
            "dry_run":         self.dry_run,
            "total_findings":  self.total_findings,
            "critical":        self.total_critical,
            "high":            self.total_high,
            "stig_cat1":       self.stig_result.open_cat1 if self.stig_result else 0,
            "stig_cat2":       self.stig_result.open_cat2 if self.stig_result else 0,
            "poam_added":      self.poam_delta.added    if self.poam_delta else 0,
            "poam_closed":     self.poam_delta.closed   if self.poam_delta else 0,
            "poam_overdue":    self.poam_delta.overdue  if self.poam_delta else 0,
            "emass_controls_updated": self.emass_sync.controls_updated if self.emass_sync else 0,
            "emass_poams_added":      self.emass_sync.poams_added      if self.emass_sync else 0,
            "alerts_sent":     self.alerts_sent,
            "error":           self.error,
        }


# ── eMASS REST API client ──────────────────────────────────────────────────────

class EMassClient:
    """
    Thin client for the eMASS REST API.

    Handles authentication (X-api-key header), error handling,
    and request/response serialization.

    Reference: eMASS User Guide v9.x Appendix B (REST API)
    """

    def __init__(
        self,
        base_url: str = EMASS_URL,
        api_key: str  = EMASS_API_KEY,
        system_id: int = EMASS_SYSTEM_ID,
        user_uid: int  = EMASS_USER_UID,
        dry_run: bool  = CONMON_DRY_RUN,
    ):
        self.base_url   = base_url.rstrip("/")
        self.api_key    = api_key
        self.system_id  = system_id
        self.user_uid   = user_uid
        self.dry_run    = dry_run
        self._session: Any = None

    def _get_session(self) -> Any:
        if self._session is None:
            try:
                import requests
                s = requests.Session()
                s.headers.update({
                    "X-api-key":   self.api_key,
                    "user-uid":    str(self.user_uid),
                    "Content-Type": "application/json",
                    "Accept":       "application/json",
                })
                self._session = s
            except ImportError:
                raise RuntimeError("requests not installed — pip install requests")
        return self._session

    def is_configured(self) -> bool:
        return bool(self.base_url and self.api_key and self.system_id)

    def get_controls(self) -> list[dict[str, Any]]:
        """GET /api/v3/systems/{systemId}/controls — retrieve current control statuses."""
        if self.dry_run or not self.is_configured():
            return []
        try:
            r = self._get_session().get(
                f"{self.base_url}/api/v3/systems/{self.system_id}/controls",
                timeout=30,
            )
            r.raise_for_status()
            return r.json().get("data", [])
        except Exception as exc:
            logger.warning("eMASS GET controls failed: %s", exc)
            return []

    def put_controls(self, controls: list[dict[str, Any]]) -> eMASSSyncResult:
        """PUT /api/v3/systems/{systemId}/controls — update control statuses."""
        if self.dry_run:
            logger.info("eMASS [DRY RUN]: would update %d controls", len(controls))
            return eMASSSyncResult(controls_updated=len(controls), poams_added=0, poams_updated=0)
        if not self.is_configured():
            return eMASSSyncResult(controls_updated=0, poams_added=0, poams_updated=0,
                                   error="eMASS not configured (EMASS_URL/EMASS_API_KEY/EMASS_SYSTEM_ID)")
        try:
            r = self._get_session().put(
                f"{self.base_url}/api/v3/systems/{self.system_id}/controls",
                json={"controls": controls},
                timeout=60,
            )
            r.raise_for_status()
            return eMASSSyncResult(controls_updated=len(controls), poams_added=0, poams_updated=0)
        except Exception as exc:
            logger.error("eMASS PUT controls failed: %s", exc)
            return eMASSSyncResult(controls_updated=0, poams_added=0, poams_updated=0,
                                   error=str(exc))

    def post_poams(self, poams: list[dict[str, Any]]) -> int:
        """POST /api/v3/systems/{systemId}/poams — add new POA&M items. Returns count added."""
        if self.dry_run:
            logger.info("eMASS [DRY RUN]: would add %d POA&M items", len(poams))
            return len(poams)
        if not self.is_configured() or not poams:
            return 0
        try:
            r = self._get_session().post(
                f"{self.base_url}/api/v3/systems/{self.system_id}/poams",
                json={"poams": poams},
                timeout=60,
            )
            r.raise_for_status()
            return len(r.json().get("data", poams))
        except Exception as exc:
            logger.error("eMASS POST poams failed: %s", exc)
            return 0

    def post_artifact(self, filename: str, content: bytes, mime_type: str = "text/csv") -> Optional[str]:
        """POST /api/v3/systems/{systemId}/artifacts — upload monthly report artifact."""
        if self.dry_run:
            logger.info("eMASS [DRY RUN]: would upload artifact %s (%d bytes)", filename, len(content))
            return f"dry-run-artifact-{uuid.uuid4().hex[:8]}"
        if not self.is_configured():
            return None
        try:
            r = self._get_session().post(
                f"{self.base_url}/api/v3/systems/{self.system_id}/artifacts",
                files={"Artifact": (filename, io.BytesIO(content), mime_type)},
                timeout=120,
            )
            r.raise_for_status()
            data = r.json().get("data", [{}])
            return data[0].get("filename", filename) if data else filename
        except Exception as exc:
            logger.error("eMASS POST artifact failed: %s", exc)
            return None


# ── Alert / notification helpers ──────────────────────────────────────────────

def _send_siem_alert(result: ConMonRunResult) -> bool:
    """POST ConMon summary to SIEM webhook."""
    if not CONMON_SIEM_URL:
        return False
    try:
        import requests
        payload = {
            "event_type":    "conmon_run",
            "source":        "aegis",
            "severity":      "critical" if result.total_critical > 0 else "high" if result.total_high > 0 else "info",
            "timestamp":     result.completed_at,
            **result.to_summary(),
        }
        resp = requests.post(CONMON_SIEM_URL, json=payload, timeout=15)
        resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("ConMon SIEM alert failed: %s", exc)
        return False


def _send_slack_alert(result: ConMonRunResult) -> bool:
    """POST ConMon summary to Slack webhook."""
    if not CONMON_SLACK_URL:
        return False
    try:
        import requests
        summary = result.to_summary()
        color   = "#d63031" if result.total_critical > 0 else \
                  "#e17055" if result.total_high > 0 else "#00b894"
        dr_tag  = " `DRY RUN`" if result.dry_run else ""
        payload = {
            "attachments": [{
                "color":    color,
                "title":    f"Aegis ConMon Run Complete{dr_tag}",
                "text":     (
                    f"*Run ID:* `{summary['run_id']}`\n"
                    f"*Findings:* {summary['total_findings']} total, "
                    f":red_circle: {summary['critical']} critical, "
                    f":large_orange_circle: {summary['high']} high\n"
                    f"*STIG:* CAT I: {summary['stig_cat1']}, CAT II: {summary['stig_cat2']}\n"
                    f"*POA&M:* +{summary['poam_added']} new, {summary['poam_closed']} closed, "
                    f"{summary['poam_overdue']} overdue\n"
                    f"*eMASS:* {summary['emass_controls_updated']} controls updated, "
                    f"{summary['emass_poams_added']} POA&Ms added"
                ),
                "footer": "Aegis CSPM",
                "ts":     int(time.time()),
            }],
        }
        resp = requests.post(CONMON_SLACK_URL, json=payload, timeout=15)
        resp.raise_for_status()
        return True
    except Exception as exc:
        logger.warning("ConMon Slack alert failed: %s", exc)
        return False


# ── ConMon Pipeline ────────────────────────────────────────────────────────────

class ConMonPipeline:
    """
    Executes the full ConMon pipeline:
      SCAN → ASSESS → REPORT → PUSH → ALERT

    Can be run synchronously (for background threads) or invoked from the
    Aegis scheduler (POST /api/conmon/run) and the ConMon scheduled task.
    """

    def __init__(self, dry_run: bool = CONMON_DRY_RUN) -> None:
        self.dry_run    = dry_run
        self.emass      = EMassClient(dry_run=dry_run)
        self._run_cache: Optional[ConMonRunResult] = None

    @property
    def last_run(self) -> Optional[ConMonRunResult]:
        return self._run_cache

    def run(self) -> ConMonRunResult:
        """
        Execute the full ConMon pipeline. Returns ConMonRunResult.

        Stages:
          1. SCAN    — cloud, K8s, IaC, ACAS/Nessus scanners
          2. ASSESS  — STIG checks + SSP control re-assessment
          3. REPORT  — generate eMASS JSON + CSV
          4. PUSH    — PUT controls + POST POA&M to eMASS
          5. ALERT   — SIEM + Slack notifications
        """
        run_id     = f"conmon-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:6]}"
        started_at = datetime.now(timezone.utc).isoformat()
        logger.info("ConMon run started: %s (dry_run=%s)", run_id, self.dry_run)

        result = ConMonRunResult(
            run_id=run_id, started_at=started_at, completed_at="", stage="SCAN",
            dry_run=self.dry_run,
        )

        try:
            # ── Stage 1: SCAN ──────────────────────────────────────────────────
            result.scan_results = self._run_scanners()
            result.stage = "ASSESS"

            # ── Stage 2: ASSESS ────────────────────────────────────────────────
            result.stig_result = self._run_stig_check()
            ssp = self._build_ssp()
            result.stage = "REPORT"

            # ── Stage 3: REPORT ────────────────────────────────────────────────
            poam_items = [p for p in ssp.poam if p]
            result.poam_delta = POAMDelta(
                added=len(poam_items),
                closed=0,    # require eMASS GET to compute delta
                updated=0,
                overdue=sum(
                    1 for p in poam_items
                    if p.scheduled_completion < datetime.now(timezone.utc).strftime("%Y-%m-%d")
                ),
            )
            result.stage = "PUSH"

            # ── Stage 4: PUSH to eMASS ─────────────────────────────────────────
            emass_controls = json.loads(ssp.to_emass_json()).get("controls", [])
            emass_poams    = self._format_poam_for_emass(ssp.poam)

            sync = self.emass.put_controls(emass_controls)
            sync.poams_added  = self.emass.post_poams(emass_poams)

            # Upload monthly report CSV artifact
            csv_content  = ssp.to_emass_csv().encode("utf-8")
            csv_filename = f"aegis_conmon_{datetime.now(timezone.utc).strftime('%Y%m')}.csv"
            artifact_id  = self.emass.post_artifact(csv_filename, csv_content)
            sync.artifact_id = artifact_id

            result.emass_sync = sync
            result.stage = "ALERT"

            # ── Stage 5: ALERT ─────────────────────────────────────────────────
            alerts = 0
            if _send_siem_alert(result):
                alerts += 1
            if _send_slack_alert(result):
                alerts += 1
            result.alerts_sent = alerts
            result.stage = "COMPLETE"

        except Exception as exc:
            logger.error("ConMon run %s failed at stage %s: %s", run_id, result.stage, exc)
            result.error = str(exc)
            result.stage = f"FAILED:{result.stage}"

        result.completed_at = datetime.now(timezone.utc).isoformat()
        self._run_cache = result

        elapsed = (
            datetime.fromisoformat(result.completed_at) -
            datetime.fromisoformat(result.started_at)
        ).total_seconds()

        logger.info(
            "ConMon run %s completed in %.1fs: stage=%s findings=%d critical=%d high=%d "
            "poam_added=%d emass_controls=%d",
            run_id, elapsed, result.stage,
            result.total_findings, result.total_critical, result.total_high,
            result.poam_delta.added if result.poam_delta else 0,
            result.emass_sync.controls_updated if result.emass_sync else 0,
        )
        return result

    def _run_scanners(self) -> list[ScanResult]:
        """Run all available Aegis scanners and aggregate results."""
        results: list[ScanResult] = []

        # ACAS scanner
        try:
            from modules.scanners.acas.scanner import ACASScanner, build_summary
            scanner = ACASScanner()
            if scanner.is_available():
                findings = scanner.scan()
                summary  = build_summary(findings)
                results.append(ScanResult(
                    provider="acas",
                    total=summary.total_findings,
                    critical=summary.critical,
                    high=summary.high,
                    medium=summary.medium,
                    low=summary.low,
                    new_findings=summary.total_findings,  # no delta baseline in v2.10
                    iavm_open=summary.iavm_open,
                ))
                logger.info("ConMon ACAS: %d findings (%d critical, %d high, %d IAVM)",
                            summary.total_findings, summary.critical, summary.high, summary.iavm_open)
        except Exception as exc:
            logger.warning("ConMon ACAS scanner error: %s", exc)

        # Cloud scanners (AWS / Azure / GCP)
        cloud_providers = [
            ("aws",   "modules.scanners.aws.scanner",   "AWSScanner"),
            ("azure", "modules.scanners.azure.scanner", "AzureScanner"),
            ("gcp",   "modules.scanners.gcp.scanner",   "GCPScanner"),
        ]
        for provider, module_path, class_name in cloud_providers:
            try:
                import importlib
                mod  = importlib.import_module(module_path)
                cls  = getattr(mod, class_name)
                s    = cls()
                if s.is_available():
                    findings = s.scan()
                    crit = sum(1 for f in findings if getattr(f, "severity", "") == "critical")
                    high = sum(1 for f in findings if getattr(f, "severity", "") == "high")
                    med  = sum(1 for f in findings if getattr(f, "severity", "") == "medium")
                    low  = sum(1 for f in findings if getattr(f, "severity", "") == "low")
                    results.append(ScanResult(
                        provider=provider, total=len(findings),
                        critical=crit, high=high, medium=med, low=low, new_findings=len(findings),
                    ))
                    logger.info("ConMon %s: %d findings", provider.upper(), len(findings))
            except Exception as exc:
                logger.debug("ConMon %s scanner error: %s", provider, exc)

        # K8s scanner
        if os.getenv("K8S_ENABLED", "false").lower() == "true":
            try:
                from modules.scanners.k8s.scanner import K8sScanner
                s = K8sScanner()
                if s.is_available():
                    findings = s.scan()
                    crit = sum(1 for f in findings if getattr(f, "severity", "") == "critical")
                    high = sum(1 for f in findings if getattr(f, "severity", "") == "high")
                    results.append(ScanResult(
                        provider="k8s", total=len(findings),
                        critical=crit, high=high, medium=0, low=0, new_findings=len(findings),
                    ))
            except Exception as exc:
                logger.debug("ConMon K8s scanner error: %s", exc)

        return results

    def _run_stig_check(self) -> STIGResult:
        """Run STIG automated checks and return aggregate result."""
        try:
            from modules.compliance.stig import STIGChecker, STIGStatus
            checker = STIGChecker()
            results = checker.run_all()
            passed   = sum(1 for r in results if r.status == STIGStatus.PASS)
            failed   = sum(1 for r in results if r.status == STIGStatus.FAIL)
            na       = sum(1 for r in results if r.status == STIGStatus.NOT_APPLICABLE)
            cat1     = sum(1 for r in results if r.status == STIGStatus.FAIL and "CAT_I"  in getattr(r, "tags", []))
            cat2     = sum(1 for r in results if r.status == STIGStatus.FAIL and "CAT_II" in getattr(r, "tags", []))
            cat3     = sum(1 for r in results if r.status == STIGStatus.FAIL and "CAT_III" in getattr(r, "tags", []))
            logger.info("ConMon STIG: %d passed, %d failed (CAT I:%d, II:%d, III:%d)",
                        passed, failed, cat1, cat2, cat3)
            return STIGResult(
                total_checks=len(results), passed=passed, failed=failed,
                not_applicable=na, open_cat1=cat1, open_cat2=cat2, open_cat3=cat3,
            )
        except Exception as exc:
            logger.warning("ConMon STIG check error: %s", exc)
            return STIGResult(
                total_checks=0, passed=0, failed=0,
                not_applicable=0, open_cat1=0, open_cat2=0, open_cat3=0,
            )

    def _build_ssp(self) -> Any:
        """Build the SSP from live posture data for report generation."""
        from modules.compliance.ssp_generator import AegisSspGenerator
        return AegisSspGenerator().build()

    @staticmethod
    def _format_poam_for_emass(poam_entries: list[Any]) -> list[dict[str, Any]]:
        """Convert AegisSsp POA&M entries to eMASS API format."""
        result = []
        for p in poam_entries:
            result.append({
                "status":                 p.status,
                "vulnerabilityDescription": p.weakness,
                "sourceIdentifyingVulnerability": p.source,
                "pocOrganization":       "Aegis Security Platform",
                "resources":             "Security Operations Team",
                "scheduledCompletionDate": p.scheduled_completion,
                "mitigations":           p.mitigation,
                "severity":              p.severity,
                "iavmNumber":            p.iavm_id or None,
                "externalUid":           p.poam_id,
                "controlAcronym":        p.control_id,
            })
        return result


# ── Startup check ──────────────────────────────────────────────────────────────

def check_conmon_config() -> dict[str, Any]:
    """
    Validate ConMon configuration at startup.
    Returns a summary dict for the startup audit event.
    """
    summary: dict[str, Any] = {
        "emass_configured": bool(EMASS_URL and EMASS_API_KEY and EMASS_SYSTEM_ID),
        "emass_url":        EMASS_URL or "NOT SET",
        "emass_system_id":  EMASS_SYSTEM_ID,
        "dry_run":          CONMON_DRY_RUN,
        "siem_configured":  bool(CONMON_SIEM_URL),
        "slack_configured": bool(CONMON_SLACK_URL),
    }

    if not EMASS_URL:
        logger.warning(
            "ConMon: EMASS_URL not set — eMASS push disabled. "
            "Set EMASS_URL + EMASS_API_KEY + EMASS_SYSTEM_ID for IL5 ConMon (CA-7)."
        )
    elif CONMON_DRY_RUN:
        logger.info("ConMon: CONFIGURED in DRY RUN mode (CONMON_DRY_RUN=true) — no eMASS writes")
    else:
        logger.info(
            "ConMon: CONFIGURED — eMASS=%s system_id=%d",
            EMASS_URL, EMASS_SYSTEM_ID,
        )

    return summary
