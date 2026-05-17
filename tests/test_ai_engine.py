"""Tests for the AI engine implementation."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyqualify.ai.engine import AIEngine
from pyqualify.models import (
    AIConfig,
    AnalysisContext,
    AnalysisMode,
    Issue,
    LogConfig,
    RawFinding,
    Severity,
)
from pyqualify.logging.logger import PyqualifyLogger


@pytest.fixture
def ai_config() -> AIConfig:
    return AIConfig(
        api_key="test-key",
        base_url="https://api.openai.com/v1",
        model="gpt-4o",
        timeout=60,
        max_retries=3,
        retry_delay=0.01,  # Short delay for tests
    )


@pytest.fixture
def logger() -> PyqualifyLogger:
    return PyqualifyLogger(LogConfig(level="DEBUG"))


@pytest.fixture
def engine(ai_config: AIConfig, logger: PyqualifyLogger) -> AIEngine:
    return AIEngine(config=ai_config, logger=logger)


@pytest.fixture
def sample_findings() -> list[RawFinding]:
    return [
        RawFinding(
            check="missing-csp-header",
            category="security-headers",
            location="https://example.com",
            evidence="No Content-Security-Policy header found",
            context={"header": "Content-Security-Policy"},
        ),
        RawFinding(
            check="missing-hsts",
            category="security-headers",
            location="https://example.com",
            evidence="No Strict-Transport-Security header found",
        ),
    ]


@pytest.fixture
def web_context() -> AnalysisContext:
    return AnalysisContext(mode=AnalysisMode.WEB, target="https://example.com")


@pytest.fixture
def valid_llm_response() -> dict:
    return {
        "issues": [
            {
                "check": "missing-csp-header",
                "severity": "high",
                "title": "Missing Content-Security-Policy Header",
                "description": "The server does not include a CSP header.",
                "evidence": "No Content-Security-Policy header in response.",
                "recommendation": "Add a Content-Security-Policy header.",
                "cwe": "CWE-693",
                "owasp": "A05:2021",
            },
            {
                "check": "missing-hsts",
                "severity": "medium",
                "title": "Missing HSTS Header",
                "description": "No Strict-Transport-Security header present.",
                "evidence": "Response lacks HSTS header.",
                "recommendation": "Add Strict-Transport-Security header.",
                "cwe": "CWE-319",
                "owasp": None,
            },
        ]
    }


class TestAIEngineInit:
    """Tests for AIEngine initialization."""

    def test_creates_openai_client(self, ai_config: AIConfig, logger: PyqualifyLogger) -> None:
        engine = AIEngine(config=ai_config, logger=logger)
        assert engine._client is not None
        assert engine._config == ai_config

    def test_creates_prompt_manager(self, engine: AIEngine) -> None:
        assert engine._prompt_manager is not None


class TestProcessFindings:
    """Tests for the process_findings method."""

    async def test_returns_empty_list_for_no_findings(
        self, engine: AIEngine, web_context: AnalysisContext
    ) -> None:
        result = await engine.process_findings([], web_context)
        assert result == []

    async def test_successful_processing(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        web_context: AnalysisContext,
        valid_llm_response: dict,
    ) -> None:
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = valid_llm_response
            result = await engine.process_findings(sample_findings, web_context)

        assert len(result) == 2
        assert result[0].check == "missing-csp-header"
        assert result[0].severity == Severity.HIGH
        assert result[1].check == "missing-hsts"
        assert result[1].severity == Severity.MEDIUM

    async def test_retries_on_failure(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        web_context: AnalysisContext,
        valid_llm_response: dict,
    ) -> None:
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = [
                Exception("API error"),
                valid_llm_response,
            ]
            result = await engine.process_findings(sample_findings, web_context)

        assert len(result) == 2
        assert mock_call.call_count == 2

    async def test_retries_up_to_max_retries(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        web_context: AnalysisContext,
    ) -> None:
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = Exception("Persistent failure")
            result = await engine.process_findings(sample_findings, web_context)

        # Should have tried 3 times (max_retries)
        assert mock_call.call_count == 3
        # Should return fallback issues
        assert len(result) == 2
        assert all(issue.severity == Severity.INFO for issue in result)

    async def test_fallback_preserves_findings(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        web_context: AnalysisContext,
    ) -> None:
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = Exception("Total failure")
            result = await engine.process_findings(sample_findings, web_context)

        assert len(result) == len(sample_findings)
        assert result[0].check == "missing-csp-header"
        assert result[1].check == "missing-hsts"
        assert "missing-csp-header" in result[0].title
        assert result[0].evidence == sample_findings[0].evidence

    async def test_retries_on_parse_error(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        web_context: AnalysisContext,
        valid_llm_response: dict,
    ) -> None:
        invalid_response = {"not_issues": []}
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.side_effect = [
                invalid_response,
                valid_llm_response,
            ]
            # The first call returns invalid data which _parse_response will reject
            # But since _call_llm returns the dict, the error happens in _parse_response
            # which is called inside process_findings try block
            result = await engine.process_findings(sample_findings, web_context)

        # Second attempt should succeed
        assert len(result) == 2

    async def test_uses_correct_prompt_for_web_mode(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        valid_llm_response: dict,
    ) -> None:
        context = AnalysisContext(mode=AnalysisMode.WEB, target="https://test.com")
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = valid_llm_response
            await engine.process_findings(sample_findings, context)

        prompt = mock_call.call_args[0][0]
        assert "WEB" in prompt
        assert "https://test.com" in prompt

    async def test_uses_correct_prompt_for_code_mode(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        valid_llm_response: dict,
    ) -> None:
        context = AnalysisContext(mode=AnalysisMode.CODE, target="/path/to/file.py")
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = valid_llm_response
            await engine.process_findings(sample_findings, context)

        prompt = mock_call.call_args[0][0]
        assert "CODE" in prompt
        assert "/path/to/file.py" in prompt

    async def test_uses_correct_prompt_for_api_mode(
        self,
        engine: AIEngine,
        sample_findings: list[RawFinding],
        valid_llm_response: dict,
    ) -> None:
        context = AnalysisContext(mode=AnalysisMode.API, target="https://api.test.com")
        with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = valid_llm_response
            await engine.process_findings(sample_findings, context)

        prompt = mock_call.call_args[0][0]
        assert "API" in prompt
        assert "https://api.test.com" in prompt


class TestCallLLM:
    """Tests for the _call_llm method."""

    async def test_timeout_raises_error(self, engine: AIEngine) -> None:
        async def slow_response(*args, **kwargs):
            await asyncio.sleep(100)

        with patch.object(engine._client.chat.completions, "create", side_effect=slow_response):
            # Override timeout to something very short for testing
            engine._config.timeout = 0.01
            with pytest.raises(asyncio.TimeoutError):
                await engine._call_llm("test prompt")

    async def test_returns_parsed_json(self, engine: AIEngine) -> None:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '{"issues": []}'

        with patch.object(
            engine._client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            result = await engine._call_llm("test prompt")

        assert result == {"issues": []}

    async def test_raises_on_invalid_json(self, engine: AIEngine) -> None:
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "not valid json"

        with patch.object(
            engine._client.chat.completions, "create", new_callable=AsyncMock
        ) as mock_create:
            mock_create.return_value = mock_response
            with pytest.raises(json.JSONDecodeError):
                await engine._call_llm("test prompt")


class TestParseResponse:
    """Tests for the _parse_response method."""

    def test_parses_valid_response(
        self, engine: AIEngine, valid_llm_response: dict
    ) -> None:
        issues = engine._parse_response(valid_llm_response)
        assert len(issues) == 2
        assert issues[0].check == "missing-csp-header"
        assert issues[0].severity == Severity.HIGH
        assert issues[0].cwe == "CWE-693"
        assert issues[0].owasp == "A05:2021"
        assert issues[1].owasp is None

    def test_rejects_non_dict_response(self, engine: AIEngine) -> None:
        with pytest.raises(ValueError, match="must be a JSON object"):
            engine._parse_response("not a dict")  # type: ignore

    def test_rejects_missing_issues_key(self, engine: AIEngine) -> None:
        with pytest.raises(ValueError, match="must contain an 'issues' array"):
            engine._parse_response({"data": []})

    def test_rejects_non_list_issues(self, engine: AIEngine) -> None:
        with pytest.raises(ValueError, match="must contain an 'issues' array"):
            engine._parse_response({"issues": "not a list"})

    def test_rejects_invalid_severity(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "extreme",
                    "title": "Test",
                    "description": "Test desc",
                    "evidence": "Test evidence",
                    "recommendation": "Test rec",
                }
            ]
        }
        with pytest.raises(ValueError, match="Invalid severity"):
            engine._parse_response(response)

    def test_rejects_missing_required_field(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "high",
                    # missing title
                    "description": "Test desc",
                    "evidence": "Test evidence",
                    "recommendation": "Test rec",
                }
            ]
        }
        with pytest.raises(ValueError, match="missing required field"):
            engine._parse_response(response)

    def test_truncates_long_title(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "low",
                    "title": "A" * 300,
                    "description": "desc",
                    "evidence": "evidence",
                    "recommendation": "rec",
                }
            ]
        }
        issues = engine._parse_response(response)
        assert len(issues[0].title) == 200

    def test_truncates_long_description(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "low",
                    "title": "title",
                    "description": "D" * 3000,
                    "evidence": "evidence",
                    "recommendation": "rec",
                }
            ]
        }
        issues = engine._parse_response(response)
        assert len(issues[0].description) == 2000

    def test_truncates_long_evidence(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "low",
                    "title": "title",
                    "description": "desc",
                    "evidence": "E" * 3000,
                    "recommendation": "rec",
                }
            ]
        }
        issues = engine._parse_response(response)
        assert len(issues[0].evidence) == 2000

    def test_truncates_long_recommendation(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "low",
                    "title": "title",
                    "description": "desc",
                    "evidence": "evidence",
                    "recommendation": "R" * 3000,
                }
            ]
        }
        issues = engine._parse_response(response)
        assert len(issues[0].recommendation) == 2000

    def test_handles_null_cwe_and_owasp(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "info",
                    "title": "Test",
                    "description": "desc",
                    "evidence": "evidence",
                    "recommendation": "rec",
                    "cwe": None,
                    "owasp": None,
                }
            ]
        }
        issues = engine._parse_response(response)
        assert issues[0].cwe is None
        assert issues[0].owasp is None

    def test_handles_empty_string_cwe_as_none(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": "test",
                    "severity": "info",
                    "title": "Test",
                    "description": "desc",
                    "evidence": "evidence",
                    "recommendation": "rec",
                    "cwe": "",
                    "owasp": "",
                }
            ]
        }
        issues = engine._parse_response(response)
        assert issues[0].cwe is None
        assert issues[0].owasp is None

    def test_parses_all_severity_levels(self, engine: AIEngine) -> None:
        response = {
            "issues": [
                {
                    "check": f"test-{sev}",
                    "severity": sev,
                    "title": f"Test {sev}",
                    "description": "desc",
                    "evidence": "evidence",
                    "recommendation": "rec",
                }
                for sev in ["critical", "high", "medium", "low", "info"]
            ]
        }
        issues = engine._parse_response(response)
        assert len(issues) == 5
        assert issues[0].severity == Severity.CRITICAL
        assert issues[4].severity == Severity.INFO


class TestFallbackIssues:
    """Tests for the _fallback_issues method."""

    def test_converts_findings_to_info_issues(self, engine: AIEngine) -> None:
        findings = [
            RawFinding(
                check="test-check",
                category="security",
                location="https://example.com",
                evidence="Some evidence here",
            )
        ]
        issues = engine._fallback_issues(findings)
        assert len(issues) == 1
        assert issues[0].severity == Severity.INFO
        assert issues[0].check == "test-check"
        assert "test-check" in issues[0].title
        assert "security" in issues[0].description
        assert issues[0].evidence == "Some evidence here"

    def test_preserves_all_findings(self, engine: AIEngine) -> None:
        findings = [
            RawFinding(check=f"check-{i}", category="cat", location="loc", evidence="ev")
            for i in range(5)
        ]
        issues = engine._fallback_issues(findings)
        assert len(issues) == 5
        for i, issue in enumerate(issues):
            assert issue.check == f"check-{i}"

