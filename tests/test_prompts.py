"""Unit tests for the PromptManager class."""

import pytest

from pyqualify.ai.prompts import PromptManager, _format_findings
from pyqualify.models import RawFinding


@pytest.fixture
def prompt_manager() -> PromptManager:
    """Create a PromptManager instance for testing."""
    return PromptManager()


@pytest.fixture
def sample_findings() -> list[RawFinding]:
    """Create sample raw findings for testing."""
    return [
        RawFinding(
            check="missing-csp-header",
            category="security",
            location="https://example.com",
            evidence="Content-Security-Policy header not found in response",
            context={"status_code": 200},
        ),
        RawFinding(
            check="missing-alt-attribute",
            category="accessibility",
            location="https://example.com/page",
            evidence='<img src="logo.png">',
            context={},
        ),
    ]


class TestFormatFindings:
    """Tests for the _format_findings helper."""

    def test_empty_findings(self) -> None:
        result = _format_findings([])
        assert result == "No raw findings provided."

    def test_single_finding_without_context(self) -> None:
        findings = [
            RawFinding(
                check="test-check",
                category="security",
                location="/path/to/file.py:10",
                evidence="found issue here",
                context={},
            )
        ]
        result = _format_findings(findings)
        assert "Finding 1:" in result
        assert "Check: test-check" in result
        assert "Category: security" in result
        assert "Location: /path/to/file.py:10" in result
        assert "Evidence: found issue here" in result
        assert "Context:" not in result

    def test_single_finding_with_context(self) -> None:
        findings = [
            RawFinding(
                check="test-check",
                category="security",
                location="https://example.com",
                evidence="header missing",
                context={"status_code": 200, "method": "GET"},
            )
        ]
        result = _format_findings(findings)
        assert "Context:" in result
        assert "status_code=200" in result
        assert "method=GET" in result

    def test_multiple_findings_numbered(self) -> None:
        findings = [
            RawFinding(
                check="check-a", category="cat-a",
                location="loc-a", evidence="ev-a",
            ),
            RawFinding(
                check="check-b", category="cat-b",
                location="loc-b", evidence="ev-b",
            ),
        ]
        result = _format_findings(findings)
        assert "Finding 1:" in result
        assert "Finding 2:" in result
        assert "Check: check-a" in result
        assert "Check: check-b" in result


class TestBuildWebPrompt:
    """Tests for PromptManager.build_web_prompt()."""

    def test_includes_analysis_mode(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert "Analysis Mode: WEB" in result

    def test_includes_target_url(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert "Target: https://example.com" in result

    def test_includes_findings(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert "missing-csp-header" in result
        assert "missing-alt-attribute" in result

    def test_includes_json_schema_instruction(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert '"issues"' in result
        assert '"severity"' in result
        assert '"check"' in result
        assert '"title"' in result
        assert '"description"' in result
        assert '"evidence"' in result
        assert '"recommendation"' in result
        assert '"cwe"' in result
        assert '"owasp"' in result

    def test_includes_severity_levels(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert '"critical"' in result
        assert '"high"' in result
        assert '"medium"' in result
        assert '"low"' in result
        assert '"info"' in result

    def test_includes_field_constraints(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert "Maximum 200 characters" in result
        assert "Maximum 2000 characters" in result

    def test_includes_web_context(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_web_prompt(sample_findings, "https://example.com")
        assert "web application" in result.lower() or "web" in result.lower()
        assert "security headers" in result.lower()

    def test_empty_findings(self, prompt_manager: PromptManager) -> None:
        result = prompt_manager.build_web_prompt([], "https://example.com")
        assert "No raw findings provided." in result
        assert "Analysis Mode: WEB" in result


class TestBuildCodePrompt:
    """Tests for PromptManager.build_code_prompt()."""

    def test_includes_analysis_mode(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_code_prompt(sample_findings, "/src/app.py")
        assert "Analysis Mode: CODE" in result

    def test_includes_target_filepath(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_code_prompt(sample_findings, "/src/app.py")
        assert "Target: /src/app.py" in result

    def test_includes_findings(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_code_prompt(sample_findings, "/src/app.py")
        assert "missing-csp-header" in result

    def test_includes_json_schema_instruction(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_code_prompt(sample_findings, "/src/app.py")
        assert '"issues"' in result
        assert '"severity"' in result
        assert '"cwe"' in result
        assert '"owasp"' in result

    def test_includes_code_context(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_code_prompt(sample_findings, "/src/app.py")
        assert "source code" in result.lower()
        assert "security vulnerabilities" in result.lower() or "security" in result.lower()

    def test_empty_findings(self, prompt_manager: PromptManager) -> None:
        result = prompt_manager.build_code_prompt([], "/src/app.py")
        assert "No raw findings provided." in result
        assert "Analysis Mode: CODE" in result


class TestBuildApiPrompt:
    """Tests for PromptManager.build_api_prompt()."""

    def test_includes_analysis_mode(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_api_prompt(sample_findings, "https://api.example.com/v1")
        assert "Analysis Mode: API" in result

    def test_includes_target_endpoint(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_api_prompt(sample_findings, "https://api.example.com/v1")
        assert "Target: https://api.example.com/v1" in result

    def test_includes_findings(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_api_prompt(sample_findings, "https://api.example.com/v1")
        assert "missing-csp-header" in result

    def test_includes_json_schema_instruction(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_api_prompt(sample_findings, "https://api.example.com/v1")
        assert '"issues"' in result
        assert '"severity"' in result
        assert '"cwe"' in result
        assert '"owasp"' in result

    def test_includes_api_context(self, prompt_manager: PromptManager, sample_findings: list[RawFinding]) -> None:
        result = prompt_manager.build_api_prompt(sample_findings, "https://api.example.com/v1")
        assert "api" in result.lower()
        assert "authentication" in result.lower()

    def test_empty_findings(self, prompt_manager: PromptManager) -> None:
        result = prompt_manager.build_api_prompt([], "https://api.example.com/v1")
        assert "No raw findings provided." in result
        assert "Analysis Mode: API" in result

