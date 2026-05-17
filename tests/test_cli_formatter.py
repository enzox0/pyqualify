"""Tests for CLIFormatter."""

import time
from unittest.mock import patch

import pytest

from pyqualify.models import (
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    Issue,
    RiskLevel,
    Severity,
)
from pyqualify.reporting.cli_formatter import CLIFormatter


@pytest.fixture
def formatter() -> CLIFormatter:
    """Create a CLIFormatter instance."""
    return CLIFormatter()


@pytest.fixture
def sample_result() -> AnalysisResult:
    """Create a sample analysis result with mixed severity issues."""
    return AnalysisResult(
        score=65,
        grade="D",
        risk_level=RiskLevel.HIGH,
        issues=[
            Issue(
                check="missing-csp",
                severity=Severity.HIGH,
                title="Missing Content-Security-Policy",
                description="No CSP header found.",
                evidence="Response headers lack CSP.",
                recommendation="Add CSP header.",
                cwe="CWE-693",
                owasp="A05:2021",
            ),
            Issue(
                check="sql-injection",
                severity=Severity.CRITICAL,
                title="SQL Injection Vulnerability",
                description="User input concatenated into SQL query.",
                evidence="query = 'SELECT * FROM users WHERE id=' + user_id",
                recommendation="Use parameterized queries.",
                cwe="CWE-89",
                owasp="A03:2021",
            ),
            Issue(
                check="missing-alt",
                severity=Severity.MEDIUM,
                title="Image Missing Alt Attribute",
                description="Image lacks alt text.",
                evidence="<img src='logo.png'>",
                recommendation="Add descriptive alt attribute.",
            ),
            Issue(
                check="unused-import",
                severity=Severity.LOW,
                title="Unused Import Detected",
                description="Import 'os' is never used.",
                evidence="import os",
                recommendation="Remove unused import.",
            ),
            Issue(
                check="og-tags-missing",
                severity=Severity.INFO,
                title="Open Graph Tags Missing",
                description="No OG tags found.",
                evidence="<head> lacks og: meta tags",
                recommendation="Add og:title, og:description tags.",
            ),
        ],
        summary="Analysis found 5 issues.",
        metadata=AnalysisMetadata(
            timestamp="2024-01-15T10:30:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        ),
    )


@pytest.fixture
def empty_result() -> AnalysisResult:
    """Create a result with no issues."""
    return AnalysisResult(
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


class TestCLIFormatterProtocol:
    """Test that CLIFormatter implements the expected interface."""

    def test_has_generate_cli_output(self, formatter: CLIFormatter) -> None:
        assert hasattr(formatter, "generate_cli_output")
        assert callable(formatter.generate_cli_output)

    def test_has_generate_html_report(self, formatter: CLIFormatter) -> None:
        assert hasattr(formatter, "generate_html_report")
        assert callable(formatter.generate_html_report)

    def test_html_report_raises_not_implemented(
        self, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        with pytest.raises(NotImplementedError):
            formatter.generate_html_report(sample_result, "output.html")


class TestColorCodedOutput:
    """Test color-coded output by severity."""

    def test_severity_colors_defined(self, formatter: CLIFormatter) -> None:
        assert formatter.SEVERITY_COLORS["critical"] == "red"
        assert formatter.SEVERITY_COLORS["high"] == "bright_red"
        assert formatter.SEVERITY_COLORS["medium"] == "yellow"
        assert formatter.SEVERITY_COLORS["low"] == "blue"
        assert formatter.SEVERITY_COLORS["info"] == "bright_black"

    @patch("click.echo")
    def test_colored_output_uses_click_style(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=True)
        # Verify click.echo was called (output was produced)
        assert mock_echo.call_count > 0


class TestSummaryBlock:
    """Test summary block display."""

    @patch("click.echo")
    def test_summary_displays_score(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        output = "\n".join(str(call.args[0]) for call in mock_echo.call_args_list if call.args)
        assert "65" in output
        assert "100" in output

    @patch("click.echo")
    def test_summary_displays_grade(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        output = "\n".join(str(call.args[0]) for call in mock_echo.call_args_list if call.args)
        assert "D" in output

    @patch("click.echo")
    def test_summary_displays_risk_level(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        output = "\n".join(str(call.args[0]) for call in mock_echo.call_args_list if call.args)
        assert "HIGH" in output

    @patch("click.echo")
    def test_summary_before_issues(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        """Summary block should appear before issues in output."""
        formatter.generate_cli_output(sample_result, use_color=False)
        calls = [str(call.args[0]) for call in mock_echo.call_args_list if call.args]
        output = "\n".join(calls)
        score_pos = output.find("Score:")
        issues_pos = output.find("Issues Found:")
        assert score_pos < issues_pos


class TestSeverityOrdering:
    """Test that issues are ordered from highest to lowest severity."""

    @patch("click.echo")
    def test_issues_ordered_by_severity(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        calls = [str(call.args[0]) for call in mock_echo.call_args_list if call.args]
        output = "\n".join(calls)

        # CRITICAL should appear before HIGH, HIGH before MEDIUM, etc.
        critical_pos = output.find("[CRITICAL]")
        high_pos = output.find("[HIGH]")
        medium_pos = output.find("[MEDIUM]")
        low_pos = output.find("[LOW]")
        info_pos = output.find("[INFO]")

        assert critical_pos < high_pos
        assert high_pos < medium_pos
        assert medium_pos < low_pos
        assert low_pos < info_pos


class TestProgressIndicator:
    """Test progress spinner functionality."""

    def test_start_and_stop_progress(self, formatter: CLIFormatter) -> None:
        formatter.start_progress("Testing")
        time.sleep(0.3)
        assert formatter._spinner_active is True
        formatter.stop_progress()
        assert formatter._spinner_active is False

    def test_spinner_thread_runs(self, formatter: CLIFormatter) -> None:
        formatter.start_progress("Analyzing")
        time.sleep(0.2)
        assert formatter._spinner_thread is not None
        assert formatter._spinner_thread.is_alive()
        formatter.stop_progress()
        assert formatter._spinner_thread is None


class TestPlainTextFallback:
    """Test plain text output when color is unsupported."""

    @patch("click.echo")
    def test_plain_text_uses_severity_prefixes(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        calls = [str(call.args[0]) for call in mock_echo.call_args_list if call.args]
        output = "\n".join(calls)

        assert "[CRITICAL]" in output
        assert "[HIGH]" in output
        assert "[MEDIUM]" in output
        assert "[LOW]" in output
        assert "[INFO]" in output

    @patch("click.echo")
    def test_plain_text_no_ansi_codes(
        self, mock_echo, formatter: CLIFormatter, sample_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(sample_result, use_color=False)
        calls = [str(call.args[0]) for call in mock_echo.call_args_list if call.args]
        output = "\n".join(calls)
        # ANSI escape codes start with \x1b[
        assert "\x1b[" not in output


class TestEmptyResults:
    """Test handling of empty results."""

    @patch("click.echo")
    def test_no_issues_message(
        self, mock_echo, formatter: CLIFormatter, empty_result: AnalysisResult
    ) -> None:
        formatter.generate_cli_output(empty_result, use_color=False)
        calls = [str(call.args[0]) for call in mock_echo.call_args_list if call.args]
        output = "\n".join(calls)
        assert "No issues found" in output

