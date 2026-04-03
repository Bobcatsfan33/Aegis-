"""
Aegis — NIST 800-53 Rev5 Compliance Report Generator  (v2.3+)

Aggregates findings from all completed scans and produces:
  • Per-control gap analysis (which NIST controls have open findings)
  • Severity breakdown (critical / high / medium / low / info)
  • Provider breakdown (aws / azure / gcp / network / k8s / iac)
  • Overall compliance score  (0–100, weighted by severity)
  • Markdown and dict output formats

NIST 800-53 Rev5: CA-7 (Continuous Monitoring), CM-6, AU-2, RA-5.

Usage:
    from modules.reports.compliance import ComplianceReportGenerator
    generator = ComplianceReportGenerator()
    report = generator.generate(findings, metadata={"scan_count": 3})
    print(report.overall_score)
    report.to_markdown()
    report.to_dict()
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from modules.scanners.base import Finding


# Severity weights used for score calculation (higher = worse)
_SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 100,
    "high":     60,
    "medium":   30,
    "low":      10,
    "info":     2,
}

# Max possible penalty per finding tier (for score normalisation)
_MAX_PENALTY_PER_FINDING = 100


@dataclass
class ControlGap:
    """A NIST 800-53 control with one or more open findings."""
    control_id: str
    findings: List[Any] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "info"


@dataclass
class ComplianceReport:
    """
    Immutable result of a ComplianceReportGenerator.generate() call.

    Attributes:
        overall_score       — 0-100 (100 = no findings, 0 = all critical)
        total_findings      — total number of findings across all scans
        findings_by_severity — {severity: count} dict
        findings_by_provider — {provider: count} dict
        control_gaps        — list of ControlGap (controls with open findings)
        metadata            — caller-supplied metadata dict
        generated_at        — ISO-8601 timestamp of report generation
    """
    overall_score: float
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_provider: Dict[str, int]
    control_gaps: List[ControlGap]
    metadata: Dict[str, Any]
    generated_at: str

    # ── Rendering helpers ──────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "overall_score":        round(self.overall_score, 1),
            "total_findings":       self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_provider": self.findings_by_provider,
            "control_gaps": [
                {
                    "control_id":    cg.control_id,
                    "finding_count": cg.finding_count,
                    "max_severity":  cg.max_severity,
                    "findings": [
                        {
                            "resource":           f.resource,
                            "issue":              f.issue,
                            "severity":           f.severity,
                            "provider":           f.provider,
                            "remediation_hint":   f.remediation_hint,
                        }
                        for f in cg.findings
                    ],
                }
                for cg in sorted(self.control_gaps, key=lambda c: c.control_id)
            ],
            "metadata":      self.metadata,
            "generated_at":  self.generated_at,
        }

    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append("# Aegis — NIST 800-53 Rev5 Compliance Report")
        lines.append("")
        lines.append(f"**Generated:** {self.generated_at}")
        lines.append(f"**Overall Score:** {self.overall_score:.1f} / 100")
        lines.append(f"**Total Findings:** {self.total_findings}")
        lines.append("")

        # Severity summary table
        lines.append("## Findings by Severity")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = self.findings_by_severity.get(sev, 0)
            lines.append(f"| {sev.upper()} | {count} |")
        lines.append("")

        # Provider summary table
        if self.findings_by_provider:
            lines.append("## Findings by Provider")
            lines.append("")
            lines.append("| Provider | Count |")
            lines.append("|---|---|")
            for provider, count in sorted(self.findings_by_provider.items()):
                lines.append(f"| {provider} | {count} |")
            lines.append("")

        # Control gap analysis
        if self.control_gaps:
            lines.append("## NIST 800-53 Control Gaps")
            lines.append("")
            lines.append("Controls with one or more open findings:")
            lines.append("")
            for cg in sorted(self.control_gaps, key=lambda c: c.control_id):
                lines.append(f"### {cg.control_id}  *(max severity: {cg.max_severity.upper()}, {cg.finding_count} finding(s))*")
                for f in cg.findings:
                    hint = f" — *{f.remediation_hint}*" if f.remediation_hint else ""
                    lines.append(f"- **[{f.severity.upper()}]** `{f.resource}`: {f.issue}{hint}")
                lines.append("")
        else:
            lines.append("## NIST 800-53 Control Gaps")
            lines.append("")
            lines.append("*No control gaps detected — all findings are unmapped or scan results are empty.*")
            lines.append("")

        # Metadata footer
        if self.metadata:
            lines.append("## Scan Metadata")
            lines.append("")
            for k, v in self.metadata.items():
                lines.append(f"- **{k}**: {v}")
            lines.append("")

        return "\n".join(lines)


class ComplianceReportGenerator:
    """
    Aggregates a list of Finding objects into a ComplianceReport.

    Score algorithm (NIST CA-7 continuous monitoring):
      Base score = 100
      Each finding deducts:  severity_weight / max_penalty * (100 / max(total, 1)) * dampening
      Score is clamped to [0, 100].

    A deployment with zero findings scores 100.
    A deployment with 10 critical findings scores ~0.
    """

    def generate(
        self,
        findings: List[Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ComplianceReport:
        """
        Build a ComplianceReport from a list of Finding objects.

        Args:
            findings:  list of modules.scanners.base.Finding instances
            metadata:  caller-supplied dict merged into the report

        Returns:
            ComplianceReport
        """
        generated_at = datetime.now(timezone.utc).isoformat()
        metadata = metadata or {}

        # ── Severity + provider counts ─────────────────────────────────────────
        findings_by_severity: Dict[str, int] = defaultdict(int)
        findings_by_provider: Dict[str, int] = defaultdict(int)

        for f in findings:
            sev = getattr(f, "severity", "info").lower()
            prov = getattr(f, "provider", "unknown").lower()
            findings_by_severity[sev] += 1
            findings_by_provider[prov] += 1

        # ── Control gap mapping ────────────────────────────────────────────────
        control_map: Dict[str, ControlGap] = {}
        for f in findings:
            for ctrl in getattr(f, "nist_controls", []):
                if ctrl not in control_map:
                    control_map[ctrl] = ControlGap(control_id=ctrl)
                control_map[ctrl].findings.append(f)

        # ── Score calculation ──────────────────────────────────────────────────
        total = len(findings)
        if total == 0:
            score = 100.0
        else:
            total_penalty = sum(
                _SEVERITY_WEIGHT.get(getattr(f, "severity", "info").lower(), 2)
                for f in findings
            )
            # Normalise: worst case is all findings critical (weight=100 each)
            worst_case = total * _SEVERITY_WEIGHT["critical"]
            score = max(0.0, 100.0 - (total_penalty / worst_case * 100.0))

        return ComplianceReport(
            overall_score=round(score, 1),
            total_findings=total,
            findings_by_severity=dict(findings_by_severity),
            findings_by_provider=dict(findings_by_provider),
            control_gaps=list(control_map.values()),
            metadata=metadata,
            generated_at=generated_at,
        )


# ── Multi-Framework ComplianceReporter ────────────────────────────────────────

# Framework control families / categories
_FRAMEWORK_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "NIST_800_53": {
        "Access Control":        ["AC-1",  "AC-2",  "AC-3",  "AC-5",  "AC-6",  "AC-17"],
        "Audit & Accountability": ["AU-2",  "AU-6",  "AU-9",  "AU-12"],
        "Configuration Mgmt":    ["CM-2",  "CM-6",  "CM-7",  "CM-8"],
        "Contingency Planning":  ["CP-9",  "CP-10"],
        "Identification & Auth": ["IA-2",  "IA-3",  "IA-5",  "IA-8"],
        "Incident Response":     ["IR-4",  "IR-5",  "IR-6"],
        "Risk Assessment":       ["RA-3",  "RA-5",  "RA-7"],
        "System & Comm Prot":    ["SC-7",  "SC-8",  "SC-12", "SC-13", "SC-28"],
        "System & Info Integ":   ["SI-2",  "SI-3",  "SI-10"],
    },
    "NIST_AI_RMF": {
        "Govern":   ["GOVERN-1", "GOVERN-2", "GOVERN-3", "GOVERN-4", "GOVERN-5", "GOVERN-6"],
        "Map":      ["MAP-1",    "MAP-2",    "MAP-3",    "MAP-4",    "MAP-5"],
        "Measure":  ["MEASURE-1","MEASURE-2","MEASURE-3","MEASURE-4"],
        "Manage":   ["MANAGE-1", "MANAGE-2", "MANAGE-3", "MANAGE-4"],
    },
    "OWASP_LLM": {
        "Prompt Injection":       ["LLM01"],
        "Insecure Output Handling":["LLM02"],
        "Training Data Poisoning":["LLM03"],
        "Model Denial of Service":["LLM04"],
        "Supply Chain Vulns":     ["LLM05"],
        "Sensitive Info Disclosure":["LLM06"],
        "Insecure Plugin Design": ["LLM07"],
        "Excessive Agency":       ["LLM08"],
        "Overreliance":           ["LLM09"],
        "Model Theft":            ["LLM10"],
    },
    "EU_AI_ACT": {
        "Risk Management":        ["AIA-9",  "AIA-10"],
        "Data Governance":        ["AIA-10", "AIA-17"],
        "Technical Documentation":["AIA-11"],
        "Transparency":           ["AIA-13"],
        "Human Oversight":        ["AIA-14"],
        "Accuracy & Robustness":  ["AIA-15"],
        "Cybersecurity":          ["AIA-15", "AIA-16"],
    },
}

# Maps finding severity → compliance impact label
_IMPACT_LABEL: Dict[str, str] = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Informational",
}

# Framework display names
_FRAMEWORK_NAMES: Dict[str, str] = {
    "NIST_800_53":  "NIST 800-53 Rev5",
    "NIST_AI_RMF":  "NIST AI RMF",
    "OWASP_LLM":    "OWASP LLM Top 10",
    "EU_AI_ACT":    "EU AI Act",
}


@dataclass
class FrameworkSection:
    """One control family / category within a framework."""
    family: str
    controls: List[str]
    findings: List[Any] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return len(self.findings) == 0

    @property
    def max_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        for sev in order:
            if any(getattr(f, "severity", "info") == sev for f in self.findings):
                return sev
        return "info"

    def to_dict(self) -> dict:
        return {
            "family":        self.family,
            "controls":      self.controls,
            "compliant":     self.compliant,
            "finding_count": len(self.findings),
            "max_severity":  self.max_severity if self.findings else None,
        }


@dataclass
class MultiFrameworkReport:
    """
    Compliance report spanning one or more frameworks.

    Attributes:
        framework        — Framework key (e.g. ``"NIST_800_53"``)
        framework_name   — Human-readable framework name
        overall_score    — 0-100 compliance score
        sections         — Per-family control gap analysis
        findings_summary — {severity: count} across all findings
        tenant_id        — Tenant this report belongs to
        metadata         — Caller-supplied extras
        generated_at     — ISO-8601 UTC timestamp
    """
    framework: str
    framework_name: str
    overall_score: float
    sections: List[FrameworkSection]
    findings_summary: Dict[str, int]
    tenant_id: str
    metadata: Dict[str, Any]
    generated_at: str

    def to_dict(self) -> dict:
        return {
            "framework":        self.framework,
            "framework_name":   self.framework_name,
            "overall_score":    round(self.overall_score, 1),
            "sections":         [s.to_dict() for s in self.sections],
            "findings_summary": self.findings_summary,
            "tenant_id":        self.tenant_id,
            "metadata":         self.metadata,
            "generated_at":     self.generated_at,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), indent=2)


class ComplianceReporter:
    """
    Multi-framework compliance reporter.

    Generates structured compliance reports for:
      • NIST 800-53 Rev5
      • NIST AI RMF
      • OWASP LLM Top 10
      • EU AI Act

    Takes AI security events / findings as input; produces
    :class:`MultiFrameworkReport` objects suitable for JSON export,
    dashboard display, and eMASS / SSP ingestion.

    Usage::

        reporter = ComplianceReporter(tenant_id="org-123")
        report = reporter.generate(events, framework="NIST_AI_RMF")
        print(report.overall_score)
        print(report.to_json())
    """

    SUPPORTED_FRAMEWORKS = list(_FRAMEWORK_CONTROLS.keys())

    def __init__(self, tenant_id: str = "default") -> None:
        self.tenant_id = tenant_id

    # ── Core generate method ──────────────────────────────────────────────────

    def generate(
        self,
        events: List[Any],
        framework: str = "NIST_800_53",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MultiFrameworkReport:
        """
        Generate a compliance report for *framework* from *events*.

        Args:
            events:     List of dicts or objects with at least:
                        ``severity`` (str), ``event_type`` (str),
                        ``controls`` (List[str]) or ``nist_controls`` (List[str]).
            framework:  One of ``SUPPORTED_FRAMEWORKS``.
            metadata:   Optional dict merged into the report.

        Returns:
            :class:`MultiFrameworkReport`

        Raises:
            ValueError: If *framework* is not supported.
        """
        if framework not in _FRAMEWORK_CONTROLS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Choose from: {self.SUPPORTED_FRAMEWORKS}"
            )

        generated_at = datetime.now(timezone.utc).isoformat()
        metadata = metadata or {}
        families = _FRAMEWORK_CONTROLS[framework]

        # Build control → findings index
        ctrl_findings: Dict[str, List[Any]] = defaultdict(list)
        for event in events:
            # Support both Finding objects and plain dicts
            if isinstance(event, dict):
                controls = (
                    event.get("controls")
                    or event.get("nist_controls")
                    or event.get("ai_controls")
                    or []
                )
                sev = event.get("severity", "info")
            else:
                controls = (
                    getattr(event, "controls", None)
                    or getattr(event, "nist_controls", None)
                    or getattr(event, "ai_controls", None)
                    or []
                )
                sev = getattr(event, "severity", "info")

            for ctrl in controls:
                ctrl_findings[ctrl].append(event)

        # Build sections
        sections: List[FrameworkSection] = []
        for family, controls in families.items():
            family_findings: List[Any] = []
            for ctrl in controls:
                family_findings.extend(ctrl_findings.get(ctrl, []))
            # Deduplicate findings in family
            seen_ids: set = set()
            unique: List[Any] = []
            for f in family_findings:
                fid = id(f)
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    unique.append(f)
            sections.append(FrameworkSection(
                family=family,
                controls=controls,
                findings=unique,
            ))

        # Score: percent of families with zero findings
        if not sections:
            score = 100.0
        else:
            # Weight by severity — fewer critical gaps = higher score
            penalty = 0.0
            for s in sections:
                if not s.compliant:
                    w = _SEVERITY_WEIGHT.get(s.max_severity, 2)
                    penalty += w
            max_penalty = len(sections) * _SEVERITY_WEIGHT["critical"]
            score = max(0.0, 100.0 - (penalty / max_penalty * 100.0))

        # Findings summary
        findings_summary: Dict[str, int] = defaultdict(int)
        for event in events:
            sev = (
                event.get("severity", "info")
                if isinstance(event, dict)
                else getattr(event, "severity", "info")
            )
            findings_summary[sev.lower()] += 1

        return MultiFrameworkReport(
            framework=framework,
            framework_name=_FRAMEWORK_NAMES[framework],
            overall_score=round(score, 1),
            sections=sections,
            findings_summary=dict(findings_summary),
            tenant_id=self.tenant_id,
            metadata=metadata,
            generated_at=generated_at,
        )

    def generate_all_frameworks(
        self,
        events: List[Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, MultiFrameworkReport]:
        """
        Generate reports for **all** supported frameworks.

        Returns a dict of ``{framework_key: MultiFrameworkReport}``.
        """
        return {
            fw: self.generate(events, framework=fw, metadata=metadata)
            for fw in self.SUPPORTED_FRAMEWORKS
        }

    def summary(
        self,
        events: List[Any],
        frameworks: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Compact summary across multiple frameworks.

        Returns a dict suitable for a dashboard panel:
        ``{framework_name: {score, sections_failing}}``.
        """
        if frameworks is None:
            frameworks = self.SUPPORTED_FRAMEWORKS
        out: Dict[str, Any] = {}
        for fw in frameworks:
            try:
                report = self.generate(events, framework=fw)
                failing = sum(1 for s in report.sections if not s.compliant)
                out[report.framework_name] = {
                    "score":           report.overall_score,
                    "sections_total":  len(report.sections),
                    "sections_failing": failing,
                    "findings_total":  sum(report.findings_summary.values()),
                }
            except ValueError:
                pass
        return out
