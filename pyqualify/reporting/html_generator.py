"""HTML dashboard report generator."""

import os
from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from pyqualify.models import AnalysisResult, Issue, Severity


class ReportError(Exception):
    """Error during report generation."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class HTMLDashboardGenerator:
    """Generates self-contained HTML dashboard reports.

    Implements ReportGeneratorProtocol for HTML output. Produces a single
    HTML file with all CSS and JavaScript inlined, requiring no external
    dependencies or network access to view.
    """

    SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]
    SEVERITY_COLORS: dict[str, str] = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#0d6efd",
        "info": "#6c757d",
    }

    def __init__(self) -> None:
        templates_dir = Path(__file__).parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=True,
        )

    def generate_cli_output(self, result: AnalysisResult, use_color: bool = True) -> None:
        """Not implemented for HTML generator. Use CLIFormatter instead."""
        raise NotImplementedError("HTMLDashboardGenerator does not support CLI output")

    def generate_html_report(self, result: AnalysisResult, output_path: str) -> None:
        """Generate a self-contained HTML dashboard report.

        Args:
            result: The complete analysis result to render.
            output_path: File path where the HTML report will be written.

        Raises:
            ReportError: If the output path is unwritable or generation fails.
        """
        self._validate_output_path(output_path)

        template_data = self._build_template_data(result)
        template = self._env.get_template("dashboard.html")
        html_content = template.render(**template_data)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
        except OSError as e:
            raise ReportError(f"Failed to write report: {e}") from e

    def _validate_output_path(self, output_path: str) -> None:
        """Validate that the output path is writable.

        Raises:
            ReportError: If the path is invalid or unwritable.
        """
        path = Path(output_path)
        parent = path.parent

        if not parent.exists():
            raise ReportError(
                f"Output directory does not exist: {parent}"
            )

        if not os.access(str(parent), os.W_OK):
            raise ReportError(
                f"Output directory is not writable: {parent}"
            )

        # Check if file already exists and is not writable
        if path.exists() and not os.access(str(path), os.W_OK):
            raise ReportError(
                f"Output file is not writable: {path}"
            )

    def _build_template_data(self, result: AnalysisResult) -> dict:
        """Build the complete data context for the Jinja2 template."""
        severity_counts = self._count_by_severity(result.issues)
        category_counts = self._count_by_category(result.issues)
        recommendations = self._get_top_recommendations(result.issues)
        executive_summary = self._build_executive_summary(result)

        return {
            "score": result.score,
            "grade": result.grade,
            "risk_level": result.risk_level.value,
            "issues": [self._issue_to_dict(issue) for issue in result.issues],
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "recommendations": recommendations,
            "executive_summary": executive_summary,
            "metadata": {
                "timestamp": result.metadata.timestamp,
                "target": result.metadata.target,
                "mode": result.metadata.mode.value,
            },
            "severity_order": self.SEVERITY_ORDER,
            "severity_colors": self.SEVERITY_COLORS,
            "total_issues": len(result.issues),
        }

    def _count_by_severity(self, issues: list[Issue]) -> dict[str, int]:
        """Count issues grouped by severity level."""
        counts: dict[str, int] = {s: 0 for s in self.SEVERITY_ORDER}
        for issue in issues:
            counts[issue.severity.value] = counts.get(issue.severity.value, 0) + 1
        return counts

    def _count_by_category(self, issues: list[Issue]) -> dict[str, int]:
        """Count issues grouped by category (check field)."""
        counter: Counter[str] = Counter()
        for issue in issues:
            counter[issue.check] += 1
        return dict(counter.most_common())

    def _get_top_recommendations(self, issues: list[Issue], top_n: int = 5) -> list[dict]:
        """Get top N prioritized recommendations ordered by severity."""
        severity_priority = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
        sorted_issues = sorted(
            issues,
            key=lambda x: severity_priority.get(x.severity.value, 99),
        )
        recommendations = []
        seen_checks: set[str] = set()
        for issue in sorted_issues:
            if issue.check not in seen_checks and len(recommendations) < top_n:
                seen_checks.add(issue.check)
                recommendations.append({
                    "title": issue.title,
                    "severity": issue.severity.value,
                    "recommendation": issue.recommendation,
                    "check": issue.check,
                })
        return recommendations

    def _build_executive_summary(self, result: AnalysisResult) -> dict:
        """Build executive summary data."""
        highest_severity = "none"
        if result.issues:
            severity_priority = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
            highest = min(
                result.issues,
                key=lambda x: severity_priority.get(x.severity.value, 99),
            )
            highest_severity = highest.severity.value

        return {
            "total_issues": len(result.issues),
            "highest_severity": highest_severity,
            "summary": result.summary,
        }

    def _issue_to_dict(self, issue: Issue) -> dict:
        """Convert an Issue to a template-friendly dict."""
        return {
            "check": issue.check,
            "severity": issue.severity.value,
            "title": issue.title,
            "description": issue.description,
            "evidence": issue.evidence,
            "recommendation": issue.recommendation,
            "cwe": issue.cwe or "N/A",
            "owasp": issue.owasp or "N/A",
        }
