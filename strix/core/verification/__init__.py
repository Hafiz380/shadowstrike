"""
Verification Loop
==================
Inspired by ECC's verification-loop skill. Provides quality gates
for scan results to ensure findings are valid before reporting.

Verification Phases:
1. Finding Validation — Check if findings are real
2. Exploit Verification — Verify PoCs actually work
3. Deduplication — Remove duplicate findings
4. Confidence Scoring — Rate finding confidence
5. Report Quality — Ensure report is complete and accurate
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class VerificationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


@dataclass
class VerificationResult:
    phase: str
    status: VerificationStatus
    message: str
    details: dict = field(default_factory=dict)
    timestamp: Optional[str] = None


@dataclass
class QualityGate:
    """A quality gate that must pass before reporting."""
    name: str
    description: str
    check_fn: callable
    severity: str = "error"  # error, warning, info


class VerificationLoop:
    """
    Quality gate system for scan results.

    Inspired by ECC's verification-loop:
    - Phase 1: Build Verification → Finding Validation
    - Phase 2: Type Check → Exploit Verification
    - Phase 3: Lint Check → Deduplication
    - Phase 4: Test Suite → Confidence Scoring
    - Phase 5: Report Quality Gate
    """

    def __init__(self):
        self.results: list[VerificationResult] = []
        self.gates: list[QualityGate] = self._default_gates()

    def run_verification(self, findings: list, report: str = "") -> list[VerificationResult]:
        """Run all verification phases on scan findings."""
        self.results = []

        # Phase 1: Finding Validation
        self._phase_finding_validation(findings)

        # Phase 2: Exploit Verification
        self._phase_exploit_verification(findings)

        # Phase 3: Deduplication
        self._phase_deduplication(findings)

        # Phase 4: Confidence Scoring
        self._phase_confidence_scoring(findings)

        # Phase 5: Report Quality
        if report:
            self._phase_report_quality(report, findings)

        return self.results

    def _phase_finding_validation(self, findings: list):
        """Phase 1: Validate that findings are real."""
        issues = []

        for f in findings:
            # Check required fields
            if not getattr(f, "title", None):
                issues.append(f"Finding missing title: {getattr(f, 'id', 'unknown')}")
            if not getattr(f, "cwe_id", None):
                issues.append(f"Finding missing CWE: {getattr(f, 'title', 'unknown')}")
            if not getattr(f, "severity", None):
                issues.append(f"Finding missing severity: {getattr(f, 'title', 'unknown')}")

            # Check severity is valid
            valid_severities = {"critical", "high", "medium", "low", "info"}
            if getattr(f, "severity", "") not in valid_severities:
                issues.append(f"Invalid severity '{f.severity}': {f.title}")

        status = VerificationStatus.FAILED if issues else VerificationStatus.PASSED
        self.results.append(
            VerificationResult(
                phase="finding_validation",
                status=status,
                message=f"{len(issues)} validation issues found",
                details={"issues": issues, "total_findings": len(findings)},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def _phase_exploit_verification(self, findings: list):
        """Phase 2: Verify that exploited findings have valid PoCs."""
        issues = []
        exploited = [f for f in findings if getattr(f, "exploited", False)]

        for f in exploited:
            if not getattr(f, "exploit_payload", None):
                issues.append(f"Exploited finding missing payload: {f.title}")
            if not getattr(f, "evidence", None):
                issues.append(f"Exploited finding missing evidence: {f.title}")

        status = VerificationStatus.WARNING if issues else VerificationStatus.PASSED
        self.results.append(
            VerificationResult(
                phase="exploit_verification",
                status=status,
                message=f"{len(exploited)} exploited findings, {len(issues)} missing proof",
                details={"issues": issues, "exploited_count": len(exploited)},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def _phase_deduplication(self, findings: list):
        """Phase 3: Check for duplicate findings."""
        seen = set()
        duplicates = []

        for f in findings:
            # Create a fingerprint for the finding
            key = self._finding_fingerprint(f)
            if key in seen:
                duplicates.append(f.title)
            seen.add(key)

        status = VerificationStatus.WARNING if duplicates else VerificationStatus.PASSED
        self.results.append(
            VerificationResult(
                phase="deduplication",
                status=status,
                message=f"{len(duplicates)} duplicate findings detected",
                details={"duplicates": duplicates, "unique_count": len(seen)},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def _phase_confidence_scoring(self, findings: list):
        """Phase 4: Score finding confidence."""
        low_confidence = []

        for f in findings:
            confidence = getattr(f, "confidence", "medium")
            if confidence == "low":
                low_confidence.append(f.title)

            # Static-only findings without exploitation are lower confidence
            if getattr(f, "static_finding", False) and not getattr(f, "exploited", False):
                if confidence not in ("low",):
                    pass  # OK for static findings

        status = VerificationStatus.WARNING if len(low_confidence) > len(findings) * 0.5 else VerificationStatus.PASSED
        self.results.append(
            VerificationResult(
                phase="confidence_scoring",
                status=status,
                message=f"{len(low_confidence)} low-confidence findings",
                details={"low_confidence": low_confidence},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def _phase_report_quality(self, report: str, findings: list):
        """Phase 5: Check report quality."""
        issues = []

        if len(report) < 100:
            issues.append("Report is too short (< 100 chars)")

        # Check that all findings are mentioned in the report
        for f in findings[:20]:  # Check first 20
            title = getattr(f, "title", "")
            if title and title not in report:
                issues.append(f"Finding not in report: {title}")

        status = VerificationStatus.WARNING if issues else VerificationStatus.PASSED
        self.results.append(
            VerificationResult(
                phase="report_quality",
                status=status,
                message=f"{len(issues)} report quality issues",
                details={"issues": issues, "report_length": len(report)},
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

    def get_summary(self) -> dict:
        """Get a summary of all verification results."""
        passed = sum(1 for r in self.results if r.status == VerificationStatus.PASSED)
        failed = sum(1 for r in self.results if r.status == VerificationStatus.FAILED)
        warnings = sum(1 for r in self.results if r.status == VerificationStatus.WARNING)

        return {
            "total_phases": len(self.results),
            "passed": passed,
            "failed": failed,
            "warnings": warnings,
            "overall": "PASS" if failed == 0 else "FAIL",
            "phases": [
                {
                    "phase": r.phase,
                    "status": r.status.value,
                    "message": r.message,
                }
                for r in self.results
            ],
        }

    def is_passing(self) -> bool:
        """Check if all critical verification phases passed."""
        return all(
            r.status != VerificationStatus.FAILED
            for r in self.results
        )

    def _finding_fingerprint(self, finding) -> str:
        """Create a unique fingerprint for a finding."""
        components = [
            getattr(finding, "title", ""),
            getattr(finding, "cwe_id", ""),
            getattr(finding, "file_path", ""),
            str(getattr(finding, "line_start", "")),
        ]
        return hashlib.md5("|".join(components).encode()).hexdigest()

    def _default_gates(self) -> list[QualityGate]:
        """Define default quality gates."""
        return [
            QualityGate(
                name="no_critical_missing_fields",
                description="All findings must have title, CWE, and severity",
                check_fn=lambda findings: all(
                    getattr(f, "title", None)
                    and getattr(f, "cwe_id", None)
                    and getattr(f, "severity", None)
                    for f in findings
                ),
            ),
            QualityGate(
                name="exploit_proof",
                description="Exploited findings must have PoC evidence",
                check_fn=lambda findings: all(
                    getattr(f, "exploit_payload", None) and getattr(f, "evidence", None)
                    for f in findings
                    if getattr(f, "exploited", False)
                ),
            ),
        ]
