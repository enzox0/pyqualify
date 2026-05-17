"""Scoring engine for calculating score, grade, and risk level from analysis findings."""

from pyqualify.models import Issue, RiskLevel, Severity


class ScoringEngine:
    """Calculates score, grade, and risk level from analysis findings."""

    SEVERITY_PENALTIES: dict[str, int] = {
        "critical": 20,
        "high": 10,
        "medium": 5,
        "low": 2,
        "info": 0,
    }

    GRADE_THRESHOLDS: list[tuple[int, str]] = [
        (90, "A"),
        (80, "B"),
        (70, "C"),
        (60, "D"),
        (0, "F"),
    ]

    def calculate_score(self, issues: list[Issue]) -> int:
        """Calculate score from 100, subtracting penalties per issue.

        Starts at 100 and subtracts severity-based penalties for each issue.
        Result is clamped to the range 0-100.
        """
        total_penalty = sum(
            self.SEVERITY_PENALTIES.get(issue.severity.value, 0)
            for issue in issues
        )
        return max(0, 100 - total_penalty)

    def derive_grade(self, score: int) -> str:
        """Derive letter grade from numeric score.

        Thresholds: A (90-100), B (80-89), C (70-79), D (60-69), F (0-59).
        """
        for threshold, grade in self.GRADE_THRESHOLDS:
            if score >= threshold:
                return grade
        return "F"

    def derive_risk_level(self, issues: list[Issue]) -> str:
        """Derive risk level from highest severity issue present.

        Returns the highest severity category present in the issues list
        (CRITICAL > HIGH > MEDIUM > LOW). Returns LOW when no issues of
        MEDIUM severity or above exist.
        """
        severity_priority = [
            (Severity.CRITICAL, RiskLevel.CRITICAL),
            (Severity.HIGH, RiskLevel.HIGH),
            (Severity.MEDIUM, RiskLevel.MEDIUM),
        ]

        for severity, risk_level in severity_priority:
            if any(issue.severity == severity for issue in issues):
                return risk_level.value

        return RiskLevel.LOW.value
