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
