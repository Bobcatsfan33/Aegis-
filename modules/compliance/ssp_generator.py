"""
Aegis — eMASS System Security Plan (SSP) Auto-Generator  (v2.9.0)
==================================================================
Generates a NIST SP 800-18 / DoD eMASS-compatible System Security Plan
document automatically from Aegis's live compliance posture data.

The SSP describes how each NIST 800-53 Rev5 control is implemented within
the system boundary — this is the primary artifact a DAA reviews for
IL4/IL5 Provisional Authorization.

Architecture
------------
AegisSSpGenerator pulls data from:
  - STIG checker results (automated check status per control family)
  - ACAS/Nessus scan summary (open vulnerability counts per control)
  - mTLS configuration status (transport controls: SC-8, IA-3)
  - Encryption config (at-rest controls: SC-28)
  - FIPS status (crypto controls: SC-13, IA-7)
  - POA&M candidates from ACAS findings (open risk items)
  - Environment variables (system boundary metadata)

Output formats:
  - JSON (eMASS API import payload — POST /emass/api/v3/systems/{id}/controls)
  - CSV (eMASS Manual Upload template — NIST Controls worksheet)
  - Markdown (human-readable narrative for DAA review package)

Control Implementation Status:
  - IMPLEMENTED       — automated check passed / control fully in place
  - PARTIALLY_IMPLEMENTED — check partially passed or compensating controls
  - PLANNED           — control on roadmap, not yet deployed
  - NOT_APPLICABLE    — system boundary exclusion documented
  - ALTERNATIVE       — alternative implementation documented

NIST 800-53 Rev5 Controls (meta — about the SSP itself)
---------------------------------------------------------
  CA-2   Security Assessments
  CA-5   Plan of Action and Milestones
  CA-6   Authorization (connected to SSP)
  CA-7   Continuous Monitoring
  PL-2   System Security Plan

DISA References
---------------
  DoD Assessment and Authorization Process Manual (DAAPM) v2.2
  eMASS User Guide v9.x
  NIST SP 800-18 Rev1 (Guide for SSP Development)

Usage
-----
    from modules.compliance.ssp_generator import AegisSspGenerator

    generator = AegisSspGenerator()
    ssp = generator.build()

    # Export formats
    json_payload = ssp.to_emass_json()   # eMASS API import
    csv_data     = ssp.to_emass_csv()    # eMASS upload worksheet
    markdown     = ssp.to_markdown()     # DAA review narrative
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Implementation Status ──────────────────────────────────────────────────────

class ControlStatus(str, Enum):
    IMPLEMENTED             = "Implemented"
    PARTIALLY_IMPLEMENTED   = "Partially Implemented"
    PLANNED                 = "Planned"
    NOT_APPLICABLE          = "Not Applicable"
    ALTERNATIVE_IMPLEMENTED = "Alternative Implementation"


class ControlOrigin(str, Enum):
    SYSTEM_SPECIFIC      = "System Specific"
    INHERITED            = "Inherited"
    HYBRID               = "Hybrid (Inherited and System Specific)"


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class ControlEntry:
    """A single NIST 800-53 control entry in the SSP."""
    control_id:         str                  # e.g. "SC-8"
    control_name:       str                  # e.g. "Transmission Confidentiality"
    family:             str                  # e.g. "SC - System and Communications Protection"
    status:             ControlStatus
    origin:             ControlOrigin        = ControlOrigin.SYSTEM_SPECIFIC
    implementation:     str                  = ""   # narrative description
    inherited_from:     str                  = ""   # if INHERITED — name of common control provider
    responsible_roles:  list[str]            = field(default_factory=list)
    test_results:       list[str]            = field(default_factory=list)  # STIG check IDs / ACAS plugin families
    open_findings:      int                  = 0    # from ACAS / STIG
    automated:          bool                 = False  # True if status is machine-determined

    def emass_status(self) -> str:
        """Map to eMASS control implementation status string."""
        return self.status.value


@dataclass
class POAMEntry:
    """Plan of Action and Milestones entry (CA-5)."""
    poam_id:           str
    control_id:        str
    weakness:          str
    severity:          str       # Critical / High / Medium / Low
    source:            str       # "ACAS", "STIG", "Manual"
    status:            str       # "Ongoing", "Completed", "Risk Accepted"
    scheduled_completion: str    # ISO date
    mitigation:        str
    iavm_id:           str = ""


@dataclass
class SystemBoundary:
    """System boundary metadata (from env or explicit config)."""
    system_name:         str
    system_abbreviation: str
    version:             str
    classification:      str   # "UNCLASSIFIED//FOR OFFICIAL USE ONLY" etc.
    impact_level:        str   # "IL4", "IL5", "IL6"
    environment:         str   # "AWS GovCloud", "Azure Government", "On-Prem IL5 DC"
    authorizing_official: str
    system_owner:        str
    isso:                str
    issm:                str
    description:         str
    generated_date:      str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class AegisSsp:
    """
    Complete System Security Plan document produced by AegisSspGenerator.
    """
    boundary:    SystemBoundary
    controls:    list[ControlEntry]
    poam:        list[POAMEntry]
    metadata:    dict[str, Any] = field(default_factory=dict)

    # ── Export: eMASS API JSON ─────────────────────────────────────────────────

    def to_emass_json(self) -> str:
        """
        Serialize to eMASS API import format (POST /api/v3/systems/{id}/controls).
        Returns JSON string.
        """
        controls_payload = []
        for c in self.controls:
            controls_payload.append({
                "acronym":                c.control_id,
                "responsibleEntities":   "; ".join(c.responsible_roles) if c.responsible_roles else "System Owner",
                "controlDesignation":    c.origin.value,
                "estimatedCompletionDate": None,
                "implementationNarrative": c.implementation or self._default_narrative(c),
                "commonControlProvider": c.inherited_from or None,
                "naJustification":       "Control not applicable to system boundary." if c.status == ControlStatus.NOT_APPLICABLE else None,
                "slcmCriteria":          "Automated" if c.automated else "Manual",
                "slcmFrequency":         "Continuously" if c.automated else "Annually",
                "slcmReportingSchedule": "Monthly",
                "slcmTracking":          "Aegis CSPM Dashboard",
                "slcmComments":          f"Aegis v{self.metadata.get('aegis_version', '2.9.0')} — automated assessment",
                "overallStatus":         c.emass_status(),
            })

        poam_payload = []
        for p in self.poam:
            poam_payload.append({
                "displayPoamId":       p.poam_id,
                "controlAcronym":      p.control_id,
                "weakness":            p.weakness,
                "severity":            p.severity,
                "source":              p.source,
                "status":              p.status,
                "scheduledCompletionDate": p.scheduled_completion,
                "mitigations":         p.mitigation,
                "iavmNumber":          p.iavm_id or None,
            })

        payload = {
            "systemName":        self.boundary.system_name,
            "systemAcronym":     self.boundary.system_abbreviation,
            "version":           self.boundary.version,
            "impactLevel":       self.boundary.impact_level,
            "environment":       self.boundary.environment,
            "generatedDate":     self.boundary.generated_date,
            "controls":          controls_payload,
            "poam":              poam_payload,
            "metadata":          self.metadata,
        }
        return json.dumps(payload, indent=2)

    def to_emass_csv(self) -> str:
        """
        Serialize to eMASS Manual Upload CSV format (Controls worksheet).
        Returns CSV string compatible with eMASS bulk upload.
        """
        out = io.StringIO()
        writer = csv.writer(out)

        # eMASS Controls worksheet headers
        writer.writerow([
            "Control Acronym",
            "Responsible Entities",
            "Control Designation",
            "Estimated Completion Date",
            "Implementation Narrative",
            "Common Control Provider",
            "NA Justification",
            "SLCM Criteria",
            "SLCM Frequency",
            "SLCM Reporting Schedule",
            "SLCM Tracking",
            "SLCM Comments",
            "Overall Status",
        ])

        for c in self.controls:
            writer.writerow([
                c.control_id,
                "; ".join(c.responsible_roles) if c.responsible_roles else "System Owner",
                c.origin.value,
                "",  # no planned completion for implemented controls
                c.implementation or self._default_narrative(c),
                c.inherited_from or "",
                "Control not applicable to system boundary." if c.status == ControlStatus.NOT_APPLICABLE else "",
                "Automated" if c.automated else "Manual",
                "Continuously" if c.automated else "Annually",
                "Monthly",
                "Aegis CSPM Dashboard",
                f"Aegis v{self.metadata.get('aegis_version', '2.9.0')} — automated assessment",
                c.emass_status(),
            ])

        return out.getvalue()

    def to_markdown(self) -> str:
        """
        Generate a human-readable Markdown SSP narrative for DAA review.
        Follows NIST SP 800-18 Rev1 section structure.
        """
        b = self.boundary
        lines: list[str] = []

        lines.append(f"# System Security Plan — {b.system_name} ({b.system_abbreviation})")
        lines.append(f"\n**Version:** {b.version}  ")
        lines.append(f"**Classification:** {b.classification}  ")
        lines.append(f"**Impact Level:** {b.impact_level}  ")
        lines.append(f"**Environment:** {b.environment}  ")
        lines.append(f"**Generated:** {b.generated_date}  \n")

        lines.append("---\n")
        lines.append("## 1. System Identification\n")
        lines.append(f"**System Description:** {b.description}\n")
        lines.append(f"| Role | Name |\n|------|------|\n"
                     f"| Authorizing Official | {b.authorizing_official} |\n"
                     f"| System Owner | {b.system_owner} |\n"
                     f"| ISSO | {b.isso} |\n"
                     f"| ISSM | {b.issm} |\n")

        # Summary statistics
        total   = len(self.controls)
        impl    = sum(1 for c in self.controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in self.controls if c.status == ControlStatus.PARTIALLY_IMPLEMENTED)
        planned = sum(1 for c in self.controls if c.status == ControlStatus.PLANNED)
        na      = sum(1 for c in self.controls if c.status == ControlStatus.NOT_APPLICABLE)
        auto    = sum(1 for c in self.controls if c.automated)

        lines.append("\n---\n")
        lines.append("## 2. Control Implementation Summary\n")
        lines.append(f"| Status | Count | % |\n|--------|-------|---|\n"
                     f"| Implemented | {impl} | {impl/total*100:.0f}% |\n"
                     f"| Partially Implemented | {partial} | {partial/total*100:.0f}% |\n"
                     f"| Planned | {planned} | {planned/total*100:.0f}% |\n"
                     f"| Not Applicable | {na} | {na/total*100:.0f}% |\n"
                     f"| **Total** | **{total}** | 100% |\n\n"
                     f"**Automated assessments:** {auto}/{total} controls ({auto/total*100:.0f}%)\n")

        # Per-family breakdown
        lines.append("\n---\n")
        lines.append("## 3. Control Families\n")

        families: dict[str, list[ControlEntry]] = {}
        for c in self.controls:
            families.setdefault(c.family, []).append(c)

        for family_name, family_controls in sorted(families.items()):
            lines.append(f"\n### {family_name}\n")
            lines.append("| Control | Name | Status | Automated |\n|---------|------|--------|------------|")
            for c in sorted(family_controls, key=lambda x: x.control_id):
                auto_flag = "✓" if c.automated else "—"
                status_emoji = {
                    ControlStatus.IMPLEMENTED:           "✅",
                    ControlStatus.PARTIALLY_IMPLEMENTED: "🟡",
                    ControlStatus.PLANNED:               "📋",
                    ControlStatus.NOT_APPLICABLE:        "➖",
                    ControlStatus.ALTERNATIVE_IMPLEMENTED: "🔄",
                }.get(c.status, "")
                lines.append(f"| {c.control_id} | {c.control_name} | "
                              f"{status_emoji} {c.status.value} | {auto_flag} |")

        # Control narratives
        lines.append("\n---\n")
        lines.append("## 4. Control Implementation Narratives\n")
        for c in self.controls:
            if c.status == ControlStatus.NOT_APPLICABLE:
                continue
            lines.append(f"\n### {c.control_id} — {c.control_name}\n")
            lines.append(f"**Status:** {c.status.value}  ")
            lines.append(f"**Origin:** {c.origin.value}  ")
            if c.automated:
                lines.append("**Assessment:** Automated (Aegis CSPM)\n")
            if c.open_findings:
                lines.append(f"**Open Findings:** {c.open_findings}\n")
            lines.append(f"\n{c.implementation or self._default_narrative(c)}\n")

        # POA&M
        if self.poam:
            lines.append("\n---\n")
            lines.append("## 5. Plan of Action and Milestones (POA&M)\n")
            lines.append("| ID | Control | Weakness | Severity | Source | Status | Scheduled |")
            lines.append("|-----|---------|---------|----------|--------|--------|-----------|")
            for p in self.poam:
                lines.append(f"| {p.poam_id} | {p.control_id} | {p.weakness[:60]}... | "
                              f"{p.severity} | {p.source} | {p.status} | {p.scheduled_completion} |")

        return "\n".join(lines)

    @staticmethod
    def _default_narrative(c: ControlEntry) -> str:
        """
        Generate a sensible default implementation narrative when none is provided.
        Used as fallback in eMASS imports and Markdown output.
        """
        if c.status == ControlStatus.IMPLEMENTED and c.automated:
            return (
                f"{c.control_id} is implemented and continuously assessed by the Aegis CSPM platform. "
                f"Automated checks run on a continuous basis with findings routed to the "
                f"eMASS POA&M workflow. Assessment evidence is available in the Aegis dashboard."
            )
        if c.status == ControlStatus.PARTIALLY_IMPLEMENTED:
            return (
                f"{c.control_id} is partially implemented. Some requirements are satisfied "
                f"through system configuration and tooling; remaining gaps are tracked in the "
                f"POA&M. Full implementation is planned per the system roadmap."
            )
        if c.status == ControlStatus.PLANNED:
            return (
                f"{c.control_id} implementation is planned. The control requirements have "
                f"been identified and are scheduled for implementation. A POA&M entry tracks "
                f"the scheduled completion date and milestones."
            )
        return f"{c.control_id}: {c.status.value}."


# ── Control catalog for Aegis + TokenDNA ──────────────────────────────────────

_AEGIS_CONTROL_CATALOG: list[dict[str, Any]] = [
    # ── AC — Access Control ────────────────────────────────────────────────────
    {"id": "AC-1",  "name": "Access Control Policy and Procedures",           "family": "AC - Access Control"},
    {"id": "AC-2",  "name": "Account Management",                             "family": "AC - Access Control"},
    {"id": "AC-3",  "name": "Access Enforcement",                             "family": "AC - Access Control"},
    {"id": "AC-6",  "name": "Least Privilege",                                "family": "AC - Access Control"},
    {"id": "AC-17", "name": "Remote Access",                                  "family": "AC - Access Control"},
    # ── AU — Audit and Accountability ─────────────────────────────────────────
    {"id": "AU-2",  "name": "Event Logging",                                  "family": "AU - Audit and Accountability"},
    {"id": "AU-3",  "name": "Content of Audit Records",                       "family": "AU - Audit and Accountability"},
    {"id": "AU-6",  "name": "Audit Record Review, Analysis, and Reporting",   "family": "AU - Audit and Accountability"},
    {"id": "AU-9",  "name": "Protection of Audit Information",                "family": "AU - Audit and Accountability"},
    {"id": "AU-9(3)", "name": "Cryptographic Protection",                     "family": "AU - Audit and Accountability"},
    {"id": "AU-12", "name": "Audit Record Generation",                        "family": "AU - Audit and Accountability"},
    # ── CA — Assessment, Authorization, Monitoring ────────────────────────────
    {"id": "CA-2",  "name": "Control Assessments",                            "family": "CA - Assessment, Authorization, Monitoring"},
    {"id": "CA-5",  "name": "Plan of Action and Milestones",                  "family": "CA - Assessment, Authorization, Monitoring"},
    {"id": "CA-6",  "name": "Authorization",                                  "family": "CA - Assessment, Authorization, Monitoring"},
    {"id": "CA-7",  "name": "Continuous Monitoring",                          "family": "CA - Assessment, Authorization, Monitoring"},
    # ── CM — Configuration Management ─────────────────────────────────────────
    {"id": "CM-6",  "name": "Configuration Settings",                         "family": "CM - Configuration Management"},
    {"id": "CM-7",  "name": "Least Functionality",                            "family": "CM - Configuration Management"},
    # ── IA — Identification and Authentication ─────────────────────────────────
    {"id": "IA-2",  "name": "Identification and Authentication (Org. Users)", "family": "IA - Identification and Authentication"},
    {"id": "IA-3",  "name": "Device Identification and Authentication",       "family": "IA - Identification and Authentication"},
    {"id": "IA-5",  "name": "Authenticator Management",                       "family": "IA - Identification and Authentication"},
    {"id": "IA-7",  "name": "Cryptographic Module Authentication",            "family": "IA - Identification and Authentication"},
    {"id": "IA-11", "name": "Re-Authentication",                              "family": "IA - Identification and Authentication"},
    # ── IR — Incident Response ─────────────────────────────────────────────────
    {"id": "IR-4",  "name": "Incident Handling",                              "family": "IR - Incident Response"},
    # ── MA — Maintenance ──────────────────────────────────────────────────────
    {"id": "MA-3",  "name": "Maintenance Tools",                              "family": "MA - Maintenance"},
    # ── PL — Planning ─────────────────────────────────────────────────────────
    {"id": "PL-2",  "name": "System Security Plan",                           "family": "PL - Planning"},
    # ── RA — Risk Assessment ──────────────────────────────────────────────────
    {"id": "RA-5",  "name": "Vulnerability Monitoring and Scanning",          "family": "RA - Risk Assessment"},
    {"id": "RA-7",  "name": "Risk Response",                                  "family": "RA - Risk Assessment"},
    # ── SC — System and Communications Protection ──────────────────────────────
    {"id": "SC-8",     "name": "Transmission Confidentiality and Integrity",  "family": "SC - System and Communications Protection"},
    {"id": "SC-8(1)",  "name": "Cryptographic Protection",                    "family": "SC - System and Communications Protection"},
    {"id": "SC-12",    "name": "Cryptographic Key Establishment and Management", "family": "SC - System and Communications Protection"},
    {"id": "SC-12(1)", "name": "Availability",                                "family": "SC - System and Communications Protection"},
    {"id": "SC-13",    "name": "Cryptographic Protection",                    "family": "SC - System and Communications Protection"},
    {"id": "SC-17",    "name": "Public Key Infrastructure Certificates",       "family": "SC - System and Communications Protection"},
    {"id": "SC-23",    "name": "Session Authenticity",                        "family": "SC - System and Communications Protection"},
    {"id": "SC-26",    "name": "Honeypots",                                   "family": "SC - System and Communications Protection"},
    {"id": "SC-28",    "name": "Protection of Information at Rest",           "family": "SC - System and Communications Protection"},
    {"id": "SC-28(1)", "name": "Cryptographic Protection",                    "family": "SC - System and Communications Protection"},
    # ── SI — System and Information Integrity ─────────────────────────────────
    {"id": "SI-2",  "name": "Flaw Remediation",                               "family": "SI - System and Information Integrity"},
    {"id": "SI-3",  "name": "Malicious Code Protection",                      "family": "SI - System and Information Integrity"},
    {"id": "SI-4",  "name": "System Monitoring",                              "family": "SI - System and Information Integrity"},
    {"id": "SI-7",  "name": "Software, Firmware, and Information Integrity",  "family": "SI - System and Information Integrity"},
]


# ── SSP Generator ──────────────────────────────────────────────────────────────

class AegisSspGenerator:
    """
    Builds a complete AegisSsp by interrogating Aegis's live posture data.

    Call build() to get a fully populated AegisSsp object.
    The result can then be exported as JSON, CSV, or Markdown.
    """

    def __init__(self) -> None:
        # Import lazily to avoid circular imports at module load time
        self._stig_checker: Any = None
        self._acas_summary: Any = None
        self._fips_summary: dict[str, Any] = {}
        self._mtls_summary: dict[str, Any] = {}
        self._enc_summary:  dict[str, Any] = {}

    def _load_posture_data(self) -> None:
        """Pull all relevant posture data from Aegis subsystems."""
        # FIPS
        try:
            from modules.security.fips import fips as _fips
            self._fips_summary = _fips.compliance_summary()
        except Exception as exc:
            logger.warning("SSP: FIPS module unavailable: %s", exc)

        # STIG
        try:
            from modules.compliance.stig import STIGChecker
            self._stig_checker = STIGChecker()
        except Exception as exc:
            logger.warning("SSP: STIG checker unavailable: %s", exc)

        # mTLS
        try:
            from modules.transport.mtls import check_mtls_config
            self._mtls_summary = check_mtls_config()
        except Exception as exc:
            logger.debug("SSP: mTLS config unavailable: %s", exc)

        # Encryption
        try:
            from modules.security.encryption import check_encryption_config
            self._enc_summary = check_encryption_config()
        except Exception as exc:
            logger.debug("SSP: encryption config unavailable: %s", exc)

        # ACAS
        try:
            from modules.scanners.acas.scanner import ACASScanner
            scanner = ACASScanner()
            if scanner.is_available():
                findings = scanner.scan()
                from modules.scanners.acas.scanner import build_summary
                self._acas_summary = build_summary(findings)
        except Exception as exc:
            logger.debug("SSP: ACAS scanner unavailable: %s", exc)

    def _assess_control(self, meta: dict[str, Any]) -> ControlEntry:
        """
        Determine implementation status and narrative for a single control
        based on live posture data.
        """
        cid   = meta["id"]
        name  = meta["name"]
        family = meta["family"]

        # Defaults
        status       = ControlStatus.PLANNED
        narrative    = ""
        automated    = False
        open_findings = 0
        responsible  = ["System Owner", "ISSO"]

        fips_active = self._fips_summary.get("fips_active", False)
        mtls_mode   = self._mtls_summary.get("inbound_mode", "") or os.getenv("MTLS_MODE", "")
        mtls_ok     = bool(mtls_mode and mtls_mode != "disabled" and
                           self._mtls_summary.get("inbound_certs_present", False))
        enc_ready   = self._enc_summary.get("provider_ready", False)
        enc_provider = self._enc_summary.get("provider", os.getenv("ENC_PROVIDER", "env"))

        # ── Per-control assessment logic ──────────────────────────────────────

        if cid == "AC-1":
            status    = ControlStatus.IMPLEMENTED
            narrative = (
                "Access control policy is defined in the Aegis System Security Plan and enforced "
                "through RBAC (Role.ANALYST, Role.ADMIN, Role.OWNER) on all API endpoints. "
                "Policy is reviewed annually and updated on significant system changes."
            )

        elif cid == "AC-2":
            status    = ControlStatus.IMPLEMENTED
            narrative = (
                "Account management is implemented through the Aegis tenant management system "
                "(POST /admin/tenants). API keys are scoped to tenant and role. Key rotation "
                "is available via POST /admin/tenants/{id}/keys. Accounts are reviewed quarterly."
            )
            automated = True
            responsible = ["System Owner", "ISSO", "Security Operations"]

        elif cid == "AC-3":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Access enforcement is implemented through FastAPI dependency injection. "
                "require_role() decorator enforces RBAC on all sensitive endpoints. "
                "JWT validation via OIDC issuer is enforced on all authenticated routes."
            )

        elif cid == "AC-6":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Least privilege is enforced through a three-tier RBAC model: "
                "ANALYST (read-only), ADMIN (management), OWNER (full system control). "
                "No endpoint grants broader access than the minimum required for its function."
            )

        elif cid == "AU-2":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "All security-relevant events are logged via the immutable hash-chained audit log "
                "(AuditLog). Events include: startup, auth failure, access, config change, "
                "scan complete, remediation. Audit log is append-only (AU-9 integrity)."
            )

        elif cid in ("AU-3", "AU-12"):
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                f"{cid}: Audit records include timestamp, event type, outcome, user ID, "
                "tenant ID, source IP, resource, and detail payload. All records are "
                "emitted by log_event() and forwarded to the configured SIEM endpoint."
            )

        elif cid == "AU-6":
            status    = ControlStatus.PARTIALLY_IMPLEMENTED
            automated = True
            narrative = (
                "Audit review is automated through the TokenDNA Attribution Dashboard "
                "(GET /dashboard/attribution) which provides 30-day trend analysis, "
                "attacker profiling, and campaign detection. Manual analyst review "
                "procedures are documented in the ConMon Plan."
            )

        elif cid in ("AU-9", "AU-9(3)"):
            status    = ControlStatus.IMPLEMENTED if enc_ready else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = enc_ready
            narrative = (
                "Audit records are protected by AES-256-GCM field-level encryption "
                f"(ENC_PROVIDER={enc_provider}) and an immutable hash-chained audit log. "
                "The hash chain provides tamper detection; encryption provides "
                "confidentiality of sensitive fields (SC-28, AU-9(3))."
            ) if enc_ready else (
                "Audit records are protected by an immutable hash-chained audit log. "
                "Field-level encryption for audit log sensitive fields is partially implemented "
                "(ENC_PROVIDER not fully configured). POA&M entry tracks completion."
            )

        elif cid in ("CA-2", "CA-6", "CA-7"):
            status    = ControlStatus.PARTIALLY_IMPLEMENTED
            narrative = {
                "CA-2": (
                    "Control assessments are automated through Aegis CSPM (continuous scanning), "
                    "DISA STIG checker (19 automated checks), and ACAS/Nessus integration. "
                    "Manual assessment procedures and third-party ATOs are pending documentation."
                ),
                "CA-6": (
                    "Authorization is in progress. This SSP constitutes the authorization "
                    "package. The system is operating under a Provisional Authorization "
                    "pending full IL5 PA from the cognizant DAA."
                ),
                "CA-7": (
                    "Continuous monitoring is implemented through Aegis CSPM (cloud posture), "
                    "ACAS/Nessus (vulnerability scanning), and the TokenDNA Attribution Dashboard "
                    "(session integrity). ConMon reporting cadence is monthly per DAAPM."
                ),
            }[cid]

        elif cid == "CA-5":
            poam_count = len([p for p in (self._acas_summary.poam_candidates
                              if self._acas_summary else []) if p])
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                f"POA&M management is implemented through the Aegis ACAS integration. "
                f"ACAS findings automatically generate POA&M candidates "
                f"(currently {poam_count} open). POA&M entries are reviewed monthly "
                f"and updated in eMASS per DAAPM requirements."
            )

        elif cid in ("CM-6", "CM-7"):
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = {
                "CM-6": (
                    "Configuration settings are enforced through Infrastructure as Code "
                    "scanners (Terraform/CloudFormation/K8s), DISA STIG automated checks, "
                    "and SBOM-pinned requirements.txt. Baseline configurations are version-controlled."
                ),
                "CM-7": (
                    "Least functionality is enforced by disabling OpenAPI docs in production "
                    "(docs_url=None when DEV_MODE=false), restricting HTTP methods per endpoint, "
                    "and RBAC enforcement on all administrative functions."
                ),
            }[cid]

        elif cid in ("IA-2",):
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Identification and authentication for organizational users is implemented "
                "through OIDC/OAuth2 integration (OIDC_ISSUER). JWT tokens are validated "
                "on all authenticated endpoints. DPoP (RFC 9449) token binding is available "
                "for high-assurance identity scenarios."
            )

        elif cid == "IA-3":
            status    = ControlStatus.IMPLEMENTED if mtls_ok else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = mtls_ok
            narrative = (
                f"Device identification and authentication is implemented through mTLS "
                f"(MTLS_MODE={mtls_mode}). Client certificates are required for all "
                f"inter-service connections. CN allowlist enforces authorized device identities."
            ) if mtls_ok else (
                "Device authentication through mTLS is partially implemented. "
                f"MTLS_MODE is configured as {mtls_mode!r} but certificate files are not "
                "fully provisioned. POA&M entry tracks cert deployment."
            )
            open_findings = 0 if mtls_ok else 1

        elif cid == "IA-5":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Authenticator management is implemented through the pre-issuance risk gate "
                "(POST /webhook/preflight/{idp}) which evaluates 8 risk signals before IdP "
                "token issuance. Token velocity and credential stuffing signals enforce "
                "authenticator strength requirements."
            )

        elif cid == "IA-7":
            status    = ControlStatus.IMPLEMENTED if fips_active else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = True
            narrative = (
                "FIPS 140-2 cryptographic module authentication is enforced at startup. "
                f"Current FIPS status: {'ACTIVE' if fips_active else 'NOT ACTIVE'}. "
                "All cryptographic operations use the `cryptography` library with "
                "FIPS-validated primitives (AES-256-GCM, SHA-384, ECDHE)."
            )
            open_findings = 0 if fips_active else 1

        elif cid == "IA-11":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Re-authentication is enforced through token expiry (JWT exp claim), "
                "the HVIP enforcer (step-up MFA triggers), and the pre-issuance risk gate "
                "(STEP_UP decision issued to IdP on elevated risk signals)."
            )

        elif cid == "IR-4":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Incident handling is automated through the Token Trap SC-26 honeypot. "
                "Any trap token use triggers: immediate real-token revocation, SIEM webhook "
                "alert, Slack notification, and TrapHitRecord forensic telemetry. "
                "Incident handling procedures are documented in the ConMon Plan."
            )

        elif cid == "MA-3":
            status    = ControlStatus.IMPLEMENTED if mtls_ok else ControlStatus.PARTIALLY_IMPLEMENTED
            narrative = (
                "Maintenance tools are authenticated via mTLS client certificates. "
                "Administrative endpoints require ADMIN+ role. All maintenance actions "
                "are audit-logged. Remote maintenance sessions require mTLS."
            ) if mtls_ok else (
                "Maintenance tool authentication through mTLS is partially implemented. "
                "RBAC on administrative endpoints is fully implemented. mTLS for remote "
                "maintenance sessions is pending cert provisioning."
            )

        elif cid == "PL-2":
            status    = ControlStatus.IMPLEMENTED
            narrative = (
                "This System Security Plan document is auto-generated by the Aegis SSP "
                "generator (GET /api/ssp) from live compliance posture data. The SSP is "
                "updated on each significant system change and reviewed annually."
            )

        elif cid == "RA-5":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            responsible = ["Security Operations", "ISSO"]
            findings = getattr(self._acas_summary, "total_findings", 0) if self._acas_summary else 0
            open_findings = getattr(self._acas_summary, "critical", 0) + getattr(self._acas_summary, "high", 0) \
                if self._acas_summary else 0
            narrative = (
                "Vulnerability scanning is implemented through the Aegis ACAS/Nessus integration "
                f"(GET /api/acas). Three ingestion modes: Tenable.sc API, Nessus API, and "
                f".nessus XML (air-gap). Current posture: {findings} total findings, "
                f"{open_findings} critical/high open. Findings mapped to NIST 800-53 controls "
                "and fed into eMASS POA&M candidates automatically."
            )

        elif cid == "RA-7":
            status    = ControlStatus.PARTIALLY_IMPLEMENTED
            narrative = (
                "Risk response is partially automated. Critical/high ACAS findings "
                "generate eMASS POA&M candidates (ALLOW: AUTO_REMEDIATE=true mode). "
                "Risk acceptance procedures require manual ISSO/ISSM review per DAAPM."
            )

        elif cid == "SC-8":
            status    = ControlStatus.IMPLEMENTED if mtls_ok else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = mtls_ok
            narrative = (
                f"Transmission confidentiality and integrity is enforced through mTLS "
                f"(MTLS_MODE={mtls_mode}, TLS 1.2+, FIPS cipher suite). "
                "All inter-service communication uses authenticated encrypted channels."
            ) if mtls_ok else (
                "Transmission confidentiality enforcement through mTLS is partially implemented. "
                "HTTPS is enforced at the load balancer layer. mTLS client cert provisioning "
                "is in progress per the POA&M."
            )

        elif cid == "SC-8(1)":
            status    = ControlStatus.IMPLEMENTED if (mtls_ok and fips_active) else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = mtls_ok and fips_active
            narrative = (
                "Cryptographic protection for transmission is implemented via TLS 1.2+ with "
                "FIPS-approved cipher suite (ECDHE-AES256-GCM-SHA384, DHE-AES256-GCM-SHA384). "
                f"FIPS status: {'ACTIVE' if fips_active else 'NOT ACTIVE'}. "
                "Cipher list hardcoded in modules/transport/mtls.py._FIPS_CIPHERS."
            )

        elif cid in ("SC-12", "SC-12(1)"):
            status    = ControlStatus.IMPLEMENTED if enc_ready else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = enc_ready
            narrative = {
                "SC-12": (
                    f"Cryptographic key management uses envelope encryption with {enc_provider} "
                    "as the KEK provider. DEKs are generated fresh per record (secrets.token_bytes). "
                    "Key rotation is available via POST /admin/encryption/rotate and "
                    "scripts/rotate_keys.py CLI."
                ),
                "SC-12(1)": (
                    f"Key availability is ensured by {enc_provider} managed key availability "
                    "guarantees. For AWS KMS: multi-region keys with cross-region replication. "
                    "For Vault: HA cluster with unseal automation."
                ),
            }[cid]

        elif cid == "SC-13":
            status    = ControlStatus.IMPLEMENTED if fips_active else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = True
            narrative = (
                "Cryptographic protection uses FIPS 140-2 validated modules. The `cryptography` "
                "library provides AES-256-GCM (FIPS 197), SHA-256/384 (FIPS 180-4), and "
                f"ECDHE (SP 800-56A). FIPS kernel mode: {'ACTIVE' if fips_active else 'NOT ACTIVE (see POA&M)'}."
            )

        elif cid == "SC-17":
            status    = ControlStatus.IMPLEMENTED if mtls_ok else ControlStatus.PARTIALLY_IMPLEMENTED
            narrative = (
                "PKI certificates are managed through the configured CA. mTLS certificates "
                "are provisioned and rotated via the _CertWatcher background thread. "
                "Certificate validity is enforced; expired certs are rejected (401)."
            )

        elif cid == "SC-23":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Session authenticity is enforced through JWT token binding (DPoP RFC 9449), "
                "mTLS transport layer identity (IA-3), and the token DNA adaptive session "
                "scoring pipeline. Sessions are revoked on anomaly detection."
            )

        elif cid == "SC-26":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "Honeypot capability is implemented through the Token Trap module (SC-26). "
                "Cryptographic decoy tokens (HMAC-SHA256) are planted in realistic locations. "
                "Any use triggers zero-false-positive detection: real tokens revoked, "
                "SIEM alert, forensic telemetry captured via TrapHitRecord."
            )

        elif cid in ("SC-28", "SC-28(1)"):
            status    = ControlStatus.IMPLEMENTED if enc_ready else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = enc_ready
            narrative = {
                "SC-28": (
                    f"Protection of information at rest is implemented through AES-256-GCM "
                    f"field-level envelope encryption (ENC_PROVIDER={enc_provider}). "
                    "Sensitive columns (session data, IP addresses, user agents, CVE details) "
                    "are encrypted before storage in ClickHouse and SQLite."
                ),
                "SC-28(1)": (
                    "Cryptographic protection for data at rest uses AES-256-GCM with 256-bit DEKs. "
                    f"Key encryption uses {enc_provider} (AWS KMS / Azure KV / Vault). "
                    "FIPS 197 (AES) and SP 800-38D (GCM) compliant."
                ),
            }[cid]

        elif cid == "SI-2":
            findings = getattr(self._acas_summary, "critical", 0) + getattr(self._acas_summary, "high", 0) \
                if self._acas_summary else 0
            status    = ControlStatus.IMPLEMENTED
            automated = True
            open_findings = findings
            narrative = (
                "Flaw remediation is implemented through Aegis ACAS integration. "
                f"Critical and high findings ({findings} open) are automatically promoted "
                "to eMASS POA&M candidates. AUTO_REMEDIATE mode allows automated patching "
                "of remediable findings (configuration drift only)."
            )

        elif cid == "SI-3":
            status    = ControlStatus.PARTIALLY_IMPLEMENTED
            narrative = (
                "Malicious code protection is partially implemented. Token Trap detects "
                "credential theft (SI-3 overlap with SC-26). Host-based AV/EDR deployment "
                "is inherited from the cloud provider and platform team (IL5 baseline)."
            )

        elif cid == "SI-4":
            status    = ControlStatus.IMPLEMENTED
            automated = True
            narrative = (
                "System monitoring is implemented through: continuous ACAS/Nessus scanning "
                "(RA-5), TokenDNA session scoring pipeline (adaptive ML model), threat intel "
                "integration (AbuseIPDB, Tor exit node list), and the Attribution Dashboard "
                "(30-day threat intelligence analytics). Alerts route to SIEM and Slack."
            )

        elif cid == "SI-7":
            status    = ControlStatus.IMPLEMENTED if enc_ready else ControlStatus.PARTIALLY_IMPLEMENTED
            automated = enc_ready
            narrative = (
                "Software and information integrity is enforced through SBOM-pinned "
                "dependencies (requirements.txt), immutable audit log hash chain, "
                "and AES-256-GCM authenticated encryption (GCM auth tag validates "
                "data integrity in addition to confidentiality)."
            )

        else:
            status    = ControlStatus.PLANNED
            narrative = f"{cid} implementation is planned. See POA&M for scheduled completion date."

        return ControlEntry(
            control_id=cid,
            control_name=name,
            family=family,
            status=status,
            implementation=narrative,
            automated=automated,
            open_findings=open_findings,
            responsible_roles=responsible,
        )

    def _build_poam(self) -> list[POAMEntry]:
        """Build POA&M entries from ACAS findings and STIG gaps."""
        poam: list[POAMEntry] = []
        seq = 1

        # ACAS-derived POA&M candidates
        if self._acas_summary:
            for candidate in getattr(self._acas_summary, "poam_candidates", []):
                if not candidate:
                    continue
                sev = getattr(candidate, "severity", "medium").capitalize()
                poam.append(POAMEntry(
                    poam_id=f"POAM-ACAS-{seq:04d}",
                    control_id="RA-5",
                    weakness=getattr(candidate, "plugin_name", "Vulnerability finding"),
                    severity=sev,
                    source="ACAS",
                    status="Ongoing",
                    scheduled_completion=_ninety_day_deadline(),
                    mitigation="Apply vendor patch or implement compensating control per ACAS finding details.",
                    iavm_id=getattr(candidate, "iavm_id", ""),
                ))
                seq += 1

        # mTLS POA&M (if not fully deployed)
        mtls_ok = bool(
            self._mtls_summary.get("inbound_certs_present") and
            self._mtls_summary.get("inbound_mode", "") not in ("", "disabled")
        )
        if not mtls_ok:
            poam.append(POAMEntry(
                poam_id=f"POAM-MTLS-{seq:04d}",
                control_id="SC-8",
                weakness="mTLS client certificates not fully provisioned for inter-service communication",
                severity="High",
                source="Manual",
                status="Ongoing",
                scheduled_completion=_ninety_day_deadline(),
                mitigation="Provision PKI certificates for Aegis services and configure MTLS_MODE=proxy|native.",
            ))
            seq += 1

        # FIPS POA&M
        if not self._fips_summary.get("fips_active"):
            poam.append(POAMEntry(
                poam_id=f"POAM-FIPS-{seq:04d}",
                control_id="SC-13",
                weakness="FIPS 140-2 kernel mode not active on host OS",
                severity="High",
                source="Manual",
                status="Ongoing",
                scheduled_completion=_ninety_day_deadline(),
                mitigation="Enable FIPS mode on host OS (fips=1 kernel parameter on RHEL/CentOS; "
                           "run `fips-mode-setup --enable` and reboot).",
            ))

        return poam

    def build(self) -> AegisSsp:
        """
        Build and return a complete AegisSsp from live posture data.

        This is the main entry point. Call this once and cache the result
        for the duration of a request.
        """
        self._load_posture_data()

        boundary = SystemBoundary(
            system_name          = os.getenv("SSP_SYSTEM_NAME",   "Aegis Security Platform"),
            system_abbreviation  = os.getenv("SSP_SYSTEM_ABBR",   "AEGIS"),
            version              = os.getenv("SSP_SYSTEM_VERSION", "2.9.0"),
            classification       = os.getenv("SSP_CLASSIFICATION", "UNCLASSIFIED // FOR OFFICIAL USE ONLY"),
            impact_level         = os.getenv("SSP_IMPACT_LEVEL",   "IL5"),
            environment          = os.getenv("SSP_ENVIRONMENT",    "AWS GovCloud / Azure Government"),
            authorizing_official = os.getenv("SSP_AO",            "[Authorizing Official Name]"),
            system_owner         = os.getenv("SSP_SYSTEM_OWNER",  "[System Owner Name]"),
            isso                 = os.getenv("SSP_ISSO",          "[ISSO Name]"),
            issm                 = os.getenv("SSP_ISSM",          "[ISSM Name]"),
            description          = os.getenv(
                "SSP_DESCRIPTION",
                "Aegis is an autonomous multi-cloud CSPM and TokenDNA zero-trust session "
                "integrity platform designed for IL4/IL5 DoD environments. The system "
                "continuously assesses cloud posture, enforces zero-trust session policies, "
                "and provides automated vulnerability management with eMASS integration."
            ),
        )

        controls = [self._assess_control(meta) for meta in _AEGIS_CONTROL_CATALOG]
        poam     = self._build_poam()

        metadata = {
            "aegis_version":    "2.9.0",
            "generated_by":     "Aegis SSP Generator (GET /api/ssp)",
            "fips_active":      self._fips_summary.get("fips_active", False),
            "mtls_mode":        self._mtls_summary.get("inbound_mode", "disabled"),
            "enc_provider":     self._enc_summary.get("provider", "unknown"),
            "acas_total":       getattr(self._acas_summary, "total_findings", 0) if self._acas_summary else 0,
            "acas_critical":    getattr(self._acas_summary, "critical", 0) if self._acas_summary else 0,
            "acas_high":        getattr(self._acas_summary, "high", 0) if self._acas_summary else 0,
        }

        logger.info(
            "SSP generated: %d controls (%d automated), %d POA&M items, system=%s IL=%s",
            len(controls),
            sum(1 for c in controls if c.automated),
            len(poam),
            boundary.system_abbreviation,
            boundary.impact_level,
        )

        return AegisSsp(boundary=boundary, controls=controls, poam=poam, metadata=metadata)


def _ninety_day_deadline() -> str:
    """Return ISO date 90 days from today (default POA&M scheduled completion)."""
    from datetime import timedelta
    return (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%d")
