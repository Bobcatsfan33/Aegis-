"""
Tests for modules/reports/compliance.py
Covers: ComplianceReportGenerator (NIST 800-53) and ComplianceReporter (multi-framework).
All tests are self-contained; no external services required.
"""
from __future__ import annotations

import json
import pytest
from dataclasses import dataclass, field
from typing import List
from unittest.mock import patch

from modules.reports.compliance import (
    ComplianceReport,
    ComplianceReportGenerator,
    ComplianceReporter,
    ControlGap,
    FrameworkSection,
    MultiFrameworkReport,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@dataclass
class MockFinding:
    resource: str = "arn:aws:s3:::test-bucket"
    issue: str = "Bucket is public"
    severity: str = "high"
    provider: str = "aws"
    nist_controls: List[str] = field(default_factory=lambda: ["AC-3", "CM-6"])
    remediation_hint: str = "Enable block public access"


def _make_findings(n: int, severity: str = "high") -> List[MockFinding]:
    return [
        MockFinding(
            resource=f"resource-{i}",
            severity=severity,
            nist_controls=["AC-3", "CM-6"],
        )
        for i in range(n)
    ]


def _make_event(severity: str = "medium", controls: list | None = None) -> dict:
    return {
        "severity": severity,
        "event_type": "policy_violation",
        "controls": controls or ["GOVERN-1", "MAP-1"],
    }


# ── ComplianceReportGenerator Tests ──────────────────────────────────────────

class TestComplianceReportGenerator:
    def setup_method(self):
        self.gen = ComplianceReportGenerator()

    def test_empty_findings_scores_100(self):
        report = self.gen.generate([])
        assert report.overall_score == 100.0

    def test_empty_findings_zero_totals(self):
        report = self.gen.generate([])
        assert report.total_findings == 0

    def test_empty_findings_no_control_gaps(self):
        report = self.gen.generate([])
        assert report.control_gaps == []

    def test_single_critical_finding_lowers_score(self):
        findings = [MockFinding(severity="critical", nist_controls=["RA-5"])]
        report = self.gen.generate(findings)
        assert report.overall_score < 100.0

    def test_all_critical_findings_score_near_zero(self):
        findings = _make_findings(10, severity="critical")
        report = self.gen.generate(findings)
        assert report.overall_score == 0.0

    def test_info_findings_minimal_score_reduction(self):
        findings = _make_findings(2, severity="info")
        report = self.gen.generate(findings)
        # info weight=2, critical=100; 2/200 = 1% deduction → score ~99
        assert report.overall_score > 90.0

    def test_severity_counts_tracked(self):
        findings = [
            MockFinding(severity="high"),
            MockFinding(severity="medium"),
            MockFinding(severity="medium"),
        ]
        report = self.gen.generate(findings)
        assert report.findings_by_severity["high"] == 1
        assert report.findings_by_severity["medium"] == 2

    def test_provider_counts_tracked(self):
        findings = [
            MockFinding(provider="aws"),
            MockFinding(provider="aws"),
            MockFinding(provider="azure"),
        ]
        report = self.gen.generate(findings)
        assert report.findings_by_provider["aws"] == 2
        assert report.findings_by_provider["azure"] == 1

    def test_control_gaps_populated(self):
        findings = [MockFinding(nist_controls=["RA-5", "CM-6"])]
        report = self.gen.generate(findings)
        ctrl_ids = {cg.control_id for cg in report.control_gaps}
        assert "RA-5" in ctrl_ids
        assert "CM-6" in ctrl_ids

    def test_control_gap_finding_count(self):
        findings = [
            MockFinding(nist_controls=["AC-3"]),
            MockFinding(nist_controls=["AC-3"]),
        ]
        report = self.gen.generate(findings)
        ac3 = next(cg for cg in report.control_gaps if cg.control_id == "AC-3")
        assert ac3.finding_count == 2

    def test_control_gap_max_severity(self):
        findings = [
            MockFinding(severity="low",      nist_controls=["SI-2"]),
            MockFinding(severity="critical",  nist_controls=["SI-2"]),
        ]
        report = self.gen.generate(findings)
        si2 = next(cg for cg in report.control_gaps if cg.control_id == "SI-2")
        assert si2.max_severity == "critical"

    def test_generated_at_is_present(self):
        report = self.gen.generate([])
        assert report.generated_at

    def test_metadata_passthrough(self):
        meta = {"scan_count": 5, "environment": "prod"}
        report = self.gen.generate([], metadata=meta)
        assert report.metadata["scan_count"] == 5

    def test_to_dict_structure(self):
        report = self.gen.generate(_make_findings(1))
        d = report.to_dict()
        assert "overall_score" in d
        assert "control_gaps" in d
        assert "findings_by_severity" in d
        assert "generated_at" in d

    def test_to_dict_control_gap_has_findings(self):
        report = self.gen.generate(_make_findings(1))
        d = report.to_dict()
        if d["control_gaps"]:
            gap = d["control_gaps"][0]
            assert "findings" in gap
            assert "control_id" in gap

    def test_to_markdown_contains_header(self):
        report = self.gen.generate([])
        md = report.to_markdown()
        assert "NIST 800-53" in md

    def test_to_markdown_shows_score(self):
        report = self.gen.generate([])
        md = report.to_markdown()
        assert "100.0" in md

    def test_to_markdown_no_gaps_message(self):
        report = self.gen.generate([])
        md = report.to_markdown()
        assert "No control gaps" in md

    def test_score_clamped_to_zero(self):
        """Score must never go negative."""
        findings = _make_findings(100, severity="critical")
        report = self.gen.generate(findings)
        assert report.overall_score >= 0.0

    def test_finding_without_nist_controls(self):
        """Findings with no nist_controls don't crash and don't create gaps."""
        @dataclass
        class Barefinding:
            severity: str = "high"
            provider: str = "aws"

        report = self.gen.generate([Bareinding() for _ in range(2)])
        assert report.total_findings == 2
        assert report.control_gaps == []


# Fix typo used in test above
@dataclass
class Bareinding:
    severity: str = "high"
    provider: str = "aws"


# ── ComplianceReporter Tests ──────────────────────────────────────────────────

class TestComplianceReporter:
    def setup_method(self):
        self.reporter = ComplianceReporter(tenant_id="test-org")

    def test_supported_frameworks_list(self):
        fw = ComplianceReporter.SUPPORTED_FRAMEWORKS
        assert "NIST_800_53" in fw
        assert "NIST_AI_RMF" in fw
        assert "OWASP_LLM" in fw
        assert "EU_AI_ACT" in fw

    def test_generate_nist_800_53(self):
        report = self.reporter.generate([], framework="NIST_800_53")
        assert report.framework == "NIST_800_53"
        assert report.framework_name == "NIST 800-53 Rev5"

    def test_generate_nist_ai_rmf(self):
        report = self.reporter.generate([], framework="NIST_AI_RMF")
        assert report.framework_name == "NIST AI RMF"

    def test_generate_owasp_llm(self):
        report = self.reporter.generate([], framework="OWASP_LLM")
        assert report.framework_name == "OWASP LLM Top 10"

    def test_generate_eu_ai_act(self):
        report = self.reporter.generate([], framework="EU_AI_ACT")
        assert report.framework_name == "EU AI Act"

    def test_invalid_framework_raises(self):
        with pytest.raises(ValueError, match="Unsupported framework"):
            self.reporter.generate([], framework="HIPAA")

    def test_empty_events_score_100(self):
        report = self.reporter.generate([], framework="NIST_AI_RMF")
        assert report.overall_score == 100.0

    def test_tenant_id_in_report(self):
        report = self.reporter.generate([], framework="NIST_800_53")
        assert report.tenant_id == "test-org"

    def test_sections_present(self):
        report = self.reporter.generate([], framework="NIST_AI_RMF")
        assert len(report.sections) > 0

    def test_nist_ai_rmf_sections(self):
        report = self.reporter.generate([], framework="NIST_AI_RMF")
        families = {s.family for s in report.sections}
        assert "Govern" in families
        assert "Map" in families
        assert "Measure" in families
        assert "Manage" in families

    def test_events_with_controls_map_to_sections(self):
        events = [_make_event(severity="high", controls=["GOVERN-1", "GOVERN-2"])]
        report = self.reporter.generate(events, framework="NIST_AI_RMF")
        govern = next(s for s in report.sections if s.family == "Govern")
        assert not govern.compliant

    def test_unrelated_controls_dont_affect_section(self):
        events = [_make_event(severity="critical", controls=["LLM01"])]
        report = self.reporter.generate(events, framework="NIST_AI_RMF")
        # LLM01 is OWASP not NIST AI RMF → all sections should be clean
        for section in report.sections:
            assert section.compliant

    def test_owasp_section_mapping(self):
        events = [_make_event(severity="critical", controls=["LLM01"])]
        report = self.reporter.generate(events, framework="OWASP_LLM")
        pi_section = next(s for s in report.sections if "Prompt Injection" in s.family)
        assert not pi_section.compliant

    def test_findings_summary_populated(self):
        events = [
            _make_event(severity="high"),
            _make_event(severity="medium"),
            _make_event(severity="medium"),
        ]
        report = self.reporter.generate(events, framework="NIST_AI_RMF")
        assert report.findings_summary.get("high") == 1
        assert report.findings_summary.get("medium") == 2

    def test_to_dict_format(self):
        report = self.reporter.generate([], framework="NIST_800_53")
        d = report.to_dict()
        assert d["framework"] == "NIST_800_53"
        assert "sections" in d
        assert "overall_score" in d
        assert "tenant_id" in d

    def test_to_json_valid(self):
        report = self.reporter.generate([], framework="NIST_800_53")
        j = report.to_json()
        parsed = json.loads(j)
        assert parsed["framework"] == "NIST_800_53"

    def test_generated_at_present(self):
        report = self.reporter.generate([], framework="EU_AI_ACT")
        assert report.generated_at

    def test_metadata_passthrough(self):
        meta = {"environment": "staging", "version": "3.1"}
        report = self.reporter.generate([], framework="NIST_800_53", metadata=meta)
        assert report.metadata["environment"] == "staging"

    def test_generate_all_frameworks(self):
        reports = self.reporter.generate_all_frameworks([])
        assert set(reports.keys()) == set(ComplianceReporter.SUPPORTED_FRAMEWORKS)

    def test_generate_all_returns_multi_framework_reports(self):
        reports = self.reporter.generate_all_frameworks([])
        for fw, r in reports.items():
            assert isinstance(r, MultiFrameworkReport)

    def test_summary_returns_dict(self):
        result = self.reporter.summary([])
        assert isinstance(result, dict)
        assert len(result) == len(ComplianceReporter.SUPPORTED_FRAMEWORKS)

    def test_summary_contains_score(self):
        result = self.reporter.summary([])
        for name, info in result.items():
            assert "score" in info

    def test_summary_subset_of_frameworks(self):
        result = self.reporter.summary([], frameworks=["NIST_800_53"])
        assert len(result) == 1

    def test_plain_dict_events_accepted(self):
        """Reporter should handle plain dict events, not just Finding objects."""
        events = [
            {"severity": "high", "controls": ["GOVERN-1"], "event_type": "test"},
        ]
        report = self.reporter.generate(events, framework="NIST_AI_RMF")
        govern = next(s for s in report.sections if s.family == "Govern")
        assert not govern.compliant

    def test_section_compliant_flag(self):
        report = self.reporter.generate([], framework="OWASP_LLM")
        for section in report.sections:
            assert section.compliant is True

    def test_framework_section_to_dict(self):
        section = FrameworkSection(family="Govern", controls=["GOVERN-1"])
        d = section.to_dict()
        assert d["family"] == "Govern"
        assert d["compliant"] is True
        assert d["finding_count"] == 0

    def test_score_drops_with_failing_sections(self):
        all_controls = [
            "GOVERN-1", "GOVERN-2", "GOVERN-3", "GOVERN-4", "GOVERN-5", "GOVERN-6",
            "MAP-1", "MAP-2", "MAP-3", "MAP-4", "MAP-5",
            "MEASURE-1", "MEASURE-2", "MEASURE-3", "MEASURE-4",
            "MANAGE-1", "MANAGE-2", "MANAGE-3", "MANAGE-4",
        ]
        events = [_make_event(severity="critical", controls=all_controls)]
        report = self.reporter.generate(events, framework="NIST_AI_RMF")
        assert report.overall_score < 100.0
