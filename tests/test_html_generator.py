"""Tests for the HTML dashboard generator."""

import os
import tempfile
from pathlib import Path

import pytest

from pyqualify.models import (
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    Issue,
    RiskLevel,
    Severity,
)
from pyqualify.reporting.html_generator import HTMLDashboardGenerator, ReportError


@pytest.fixture
def sample_issues() -> list[Issue]:
    """Create a sample list of issues for testing."""
    return [
        Issue(
            check="missing-csp-header",
            severity=Severity.HIGH,
            title="Missing Content-Security-Policy Header",
            description="The server does not include a CSP header.",
            evidence="Response headers: {Server: nginx}",
            recommendation="Add Content-Security-Policy header with restrictive directives.",
            cwe="CWE-693",
            owasp="A05:2021",
        ),
        Issue(
            check="missing-hsts-header",
            severity=Severity.HIGH,
            title="Missing Strict-Transport-Security Header",
            description="HSTS header is not present.",
            evidence="No HSTS header found in response.",
            recommendation="Add Strict-Transport-Security header with max-age=31536000.",
            cwe="CWE-319",
            owasp="A02:2021",
        ),
        Issue(
            check="sql-injection",
            severity=Severity.CRITICAL,
            title="Potential SQL Injection",
            description="User input is concatenated directly into SQL query.",
            evidence="query = 'SELECT * FROM users WHERE id=' + user_id",
            recommendation="Use parameterized queries instead of string concatenation.",
            cwe="CWE-89",
            owasp="A03:2021",
        ),
        Issue(
            check="missing-alt",
            severity=Severity.MEDIUM,
            title="Image Missing Alt Attribute",
            description="An image element lacks an alt attribute.",
            evidence="<img src='logo.png'>",
            recommendation="Add a descriptive alt attribute to the image.",
            cwe=None,
            owasp=None,
        ),
        Issue(
            check="dead-code",
            severity=Severity.LOW,
            title="Unused Variable Detected",
            description="Variable 'temp' is assigned but never used.",
            evidence="temp = calculate_value()",
            recommendation="Remove the unused variable or use it.",
            cwe=None,
            owasp=None,
        ),
        Issue(
            check="missing-og-tags",
            severity=Severity.INFO,
            title="Missing Open Graph Tags",
            description="Page lacks Open Graph meta tags.",
            evidence="No og:title, og:description found.",
            recommendation="Add Open Graph meta tags for better social sharing.",
            cwe=None,
            owasp=None,
        ),
    ]


@pytest.fixture
def sample_result(sample_issues: list[Issue]) -> AnalysisResult:
    """Create a sample analysis result."""
    return AnalysisResult(
        score=55,
        grade="F",
        risk_level=RiskLevel.CRITICAL,
        issues=sample_issues,
        summary="Analysis found 6 issues including critical SQL injection vulnerability.",
        metadata=AnalysisMetadata(
            timestamp="2024-01-15T10:30:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        ),
    )


@pytest.fixture
def generator() -> HTMLDashboardGenerator:
    """Create an HTMLDashboardGenerator instance."""
    return HTMLDashboardGenerator()


class TestHTMLDashboardGenerator:
    """Tests for HTMLDashboardGenerator."""

    def test_generate_html_report_creates_file(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that generate_html_report creates an HTML file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)
            assert os.path.exists(output_path)

    def test_generated_html_is_self_contained(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that generated HTML has no external dependencies."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Should contain inlined CSS
            assert "<style>" in content
            # Should contain inlined JS
            assert "<script>" in content
            # Should NOT have external links
            assert 'rel="stylesheet"' not in content
            assert '<script src=' not in content
            assert '<link href=' not in content

    def test_html_contains_overview_panel(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains score, grade, and risk level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Score gauge
            assert "55" in content
            # Grade badge
            assert "grade-F" in content
            # Risk level
            assert "critical" in content.lower()

    def test_html_contains_severity_breakdown(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains severity breakdown chart."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "Severity Breakdown" in content
            # All severity levels should be present
            for severity in ["critical", "high", "medium", "low", "info"]:
                assert severity in content

    def test_html_contains_category_bars(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains issues-by-category section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "Issues by Category" in content
            assert "missing-csp-header" in content
            assert "sql-injection" in content

    def test_html_contains_filterable_issues_table(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains filterable issues table with expandable rows."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Filter controls
            assert "severity-filter" in content
            assert "category-filter" in content
            # Issue details
            assert "Missing Content-Security-Policy Header" in content
            assert "Potential SQL Injection" in content
            # Expandable details
            assert "issue-details" in content
            assert "CWE-89" in content
            assert "A03:2021" in content

    def test_html_contains_executive_summary(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains executive summary panel."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "Executive Summary" in content
            # Total issues count
            assert "6" in content
            # Summary text
            assert "SQL injection" in content

    def test_html_contains_recommendations(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that HTML contains top 5 recommendations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "Top Recommendations" in content
            # Should include the critical issue recommendation first
            assert "parameterized queries" in content

    def test_recommendations_ordered_by_severity(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that recommendations are ordered by severity descending."""
        recs = generator._get_top_recommendations(sample_result.issues)
        # First recommendation should be critical
        assert recs[0]["severity"] == "critical"
        # Second should be high
        assert recs[1]["severity"] == "high"

    def test_recommendations_limited_to_5(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that at most 5 recommendations are returned."""
        recs = generator._get_top_recommendations(sample_result.issues)
        assert len(recs) <= 5

    def test_error_on_nonexistent_directory(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that ReportError is raised for nonexistent directory."""
        with pytest.raises(ReportError, match="does not exist"):
            generator.generate_html_report(
                sample_result, "/nonexistent/path/report.html"
            )

    @pytest.mark.skipif(
        os.name == "nt",
        reason="Windows does not enforce Unix-style directory permissions via chmod",
    )
    def test_error_on_unwritable_directory(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that ReportError is raised for unwritable directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Make directory read-only
            os.chmod(tmpdir, 0o555)
            try:
                output_path = os.path.join(tmpdir, "report.html")
                with pytest.raises(ReportError, match="not writable"):
                    generator.generate_html_report(sample_result, output_path)
            finally:
                # Restore permissions for cleanup
                os.chmod(tmpdir, 0o755)

    def test_empty_issues_list(self, generator: HTMLDashboardGenerator) -> None:
        """Test HTML generation with no issues."""
        result = AnalysisResult(
            score=100,
            grade="A",
            risk_level=RiskLevel.LOW,
            issues=[],
            summary="No issues found.",
            metadata=AnalysisMetadata(
                timestamp="2024-01-15T10:30:00Z",
                target="https://example.com",
                mode=AnalysisMode.WEB,
            ),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(result, output_path)
            assert os.path.exists(output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "100" in content
            assert "grade-A" in content

    def test_severity_counts(
        self, generator: HTMLDashboardGenerator, sample_issues: list[Issue]
    ) -> None:
        """Test severity counting logic."""
        counts = generator._count_by_severity(sample_issues)
        assert counts["critical"] == 1
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 1

    def test_category_counts(
        self, generator: HTMLDashboardGenerator, sample_issues: list[Issue]
    ) -> None:
        """Test category counting logic."""
        counts = generator._count_by_category(sample_issues)
        assert counts["missing-csp-header"] == 1
        assert counts["sql-injection"] == 1

    def test_executive_summary_highest_severity(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that executive summary identifies highest severity."""
        summary = generator._build_executive_summary(sample_result)
        assert summary["highest_severity"] == "critical"
        assert summary["total_issues"] == 6

    def test_executive_summary_no_issues(
        self, generator: HTMLDashboardGenerator
    ) -> None:
        """Test executive summary with no issues."""
        result = AnalysisResult(
            score=100,
            grade="A",
            risk_level=RiskLevel.LOW,
            issues=[],
            summary="Clean.",
            metadata=AnalysisMetadata(
                timestamp="2024-01-15T10:30:00Z",
                target="https://example.com",
                mode=AnalysisMode.WEB,
            ),
        )
        summary = generator._build_executive_summary(result)
        assert summary["highest_severity"] == "none"
        assert summary["total_issues"] == 0

    def test_generate_cli_output_raises(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that generate_cli_output raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            generator.generate_cli_output(sample_result)

    def test_issue_to_dict_with_none_cwe_owasp(
        self, generator: HTMLDashboardGenerator
    ) -> None:
        """Test that None CWE/OWASP are converted to 'N/A'."""
        issue = Issue(
            check="test",
            severity=Severity.LOW,
            title="Test",
            description="Test desc",
            evidence="Test evidence",
            recommendation="Fix it",
            cwe=None,
            owasp=None,
        )
        result = generator._issue_to_dict(issue)
        assert result["cwe"] == "N/A"
        assert result["owasp"] == "N/A"

    def test_html_valid_structure(
        self, generator: HTMLDashboardGenerator, sample_result: AnalysisResult
    ) -> None:
        """Test that generated HTML has valid basic structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.html")
            generator.generate_html_report(sample_result, output_path)

            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert content.startswith("<!DOCTYPE html>")
            assert "<html" in content
            assert "</html>" in content
            assert "<head>" in content
            assert "</head>" in content
            assert "<body>" in content
            assert "</body>" in content

