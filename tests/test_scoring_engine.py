"""Unit tests for the scoring engine."""

import pytest

from pyqualify.models import Issue, Severity
from pyqualify.scoring.engine import ScoringEngine


def _make_issue(severity: Severity) -> Issue:
    """Helper to create an Issue with a given severity."""
    return Issue(
        check="test-check",
        severity=severity,
        title="Test Issue",
        description="A test issue",
        evidence="Some evidence",
        recommendation="Fix it",
    )


class TestCalculateScore:
    """Tests for ScoringEngine.calculate_score()."""

    def setup_method(self) -> None:
        self.engine = ScoringEngine()

    def test_no_issues_returns_100(self) -> None:
        assert self.engine.calculate_score([]) == 100

    def test_single_critical_issue(self) -> None:
        issues = [_make_issue(Severity.CRITICAL)]
        assert self.engine.calculate_score(issues) == 80

    def test_single_high_issue(self) -> None:
        issues = [_make_issue(Severity.HIGH)]
        assert self.engine.calculate_score(issues) == 90

    def test_single_medium_issue(self) -> None:
        issues = [_make_issue(Severity.MEDIUM)]
        assert self.engine.calculate_score(issues) == 95

    def test_single_low_issue(self) -> None:
        issues = [_make_issue(Severity.LOW)]
        assert self.engine.calculate_score(issues) == 98

    def test_single_info_issue(self) -> None:
        issues = [_make_issue(Severity.INFO)]
        assert self.engine.calculate_score(issues) == 100

    def test_multiple_issues_subtract_cumulatively(self) -> None:
        issues = [
            _make_issue(Severity.CRITICAL),
            _make_issue(Severity.HIGH),
            _make_issue(Severity.MEDIUM),
        ]
        # 100 - 20 - 10 - 5 = 65
        assert self.engine.calculate_score(issues) == 65

    def test_score_clamped_to_zero(self) -> None:
        # 6 critical issues = 120 penalty, clamped to 0
        issues = [_make_issue(Severity.CRITICAL) for _ in range(6)]
        assert self.engine.calculate_score(issues) == 0

    def test_score_never_negative(self) -> None:
        issues = [_make_issue(Severity.CRITICAL) for _ in range(10)]
        assert self.engine.calculate_score(issues) == 0

    def test_mixed_severities(self) -> None:
        issues = [
            _make_issue(Severity.HIGH),
            _make_issue(Severity.HIGH),
            _make_issue(Severity.LOW),
            _make_issue(Severity.INFO),
        ]
        # 100 - 10 - 10 - 2 - 0 = 78
        assert self.engine.calculate_score(issues) == 78


class TestDeriveGrade:
    """Tests for ScoringEngine.derive_grade()."""

    def setup_method(self) -> None:
        self.engine = ScoringEngine()

    def test_grade_a_at_100(self) -> None:
        assert self.engine.derive_grade(100) == "A"

    def test_grade_a_at_90(self) -> None:
        assert self.engine.derive_grade(90) == "A"

    def test_grade_b_at_89(self) -> None:
        assert self.engine.derive_grade(89) == "B"

    def test_grade_b_at_80(self) -> None:
        assert self.engine.derive_grade(80) == "B"

    def test_grade_c_at_79(self) -> None:
        assert self.engine.derive_grade(79) == "C"

    def test_grade_c_at_70(self) -> None:
        assert self.engine.derive_grade(70) == "C"

    def test_grade_d_at_69(self) -> None:
        assert self.engine.derive_grade(69) == "D"

    def test_grade_d_at_60(self) -> None:
        assert self.engine.derive_grade(60) == "D"

    def test_grade_f_at_59(self) -> None:
        assert self.engine.derive_grade(59) == "F"

    def test_grade_f_at_0(self) -> None:
        assert self.engine.derive_grade(0) == "F"


class TestDeriveRiskLevel:
    """Tests for ScoringEngine.derive_risk_level()."""

    def setup_method(self) -> None:
        self.engine = ScoringEngine()

    def test_no_issues_returns_low(self) -> None:
        assert self.engine.derive_risk_level([]) == "low"

    def test_only_info_issues_returns_low(self) -> None:
        issues = [_make_issue(Severity.INFO)]
        assert self.engine.derive_risk_level(issues) == "low"

    def test_only_low_issues_returns_low(self) -> None:
        issues = [_make_issue(Severity.LOW)]
        assert self.engine.derive_risk_level(issues) == "low"

    def test_medium_issue_returns_medium(self) -> None:
        issues = [_make_issue(Severity.MEDIUM)]
        assert self.engine.derive_risk_level(issues) == "medium"

    def test_high_issue_returns_high(self) -> None:
        issues = [_make_issue(Severity.HIGH)]
        assert self.engine.derive_risk_level(issues) == "high"

    def test_critical_issue_returns_critical(self) -> None:
        issues = [_make_issue(Severity.CRITICAL)]
        assert self.engine.derive_risk_level(issues) == "critical"

    def test_mixed_severities_returns_highest(self) -> None:
        issues = [
            _make_issue(Severity.LOW),
            _make_issue(Severity.MEDIUM),
            _make_issue(Severity.HIGH),
        ]
        assert self.engine.derive_risk_level(issues) == "high"

    def test_critical_overrides_all(self) -> None:
        issues = [
            _make_issue(Severity.LOW),
            _make_issue(Severity.MEDIUM),
            _make_issue(Severity.HIGH),
            _make_issue(Severity.CRITICAL),
        ]
        assert self.engine.derive_risk_level(issues) == "critical"

    def test_low_and_info_only_returns_low(self) -> None:
        issues = [
            _make_issue(Severity.LOW),
            _make_issue(Severity.INFO),
            _make_issue(Severity.LOW),
        ]
        assert self.engine.derive_risk_level(issues) == "low"

