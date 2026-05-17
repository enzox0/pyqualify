"""Tests for the API Analyzer."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pyqualify.analyzers.api_analyzer import APIAnalyzer
from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMode,
    Issue,
    LogConfig,
    RawFinding,
    Severity,
)
from pyqualify.logging.logger import PyqualifyLogger


@pytest.fixture
def mock_ai_engine():
    """Create a mock AI engine that returns issues from findings."""
    engine = AsyncMock()
    engine.process_findings = AsyncMock(return_value=[])
    return engine


@pytest.fixture
def mock_logger():
    """Create a PyqualifyLogger with minimal config."""
    return PyqualifyLogger(LogConfig(level="WARNING"))


@pytest.fixture
def mock_http_client():
    """Create a mock httpx.AsyncClient."""
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


@pytest.fixture
def analyzer(mock_ai_engine, mock_http_client, mock_logger):
    """Create an APIAnalyzer instance with mocked dependencies."""
    return APIAnalyzer(
        ai_engine=mock_ai_engine,
        http_client=mock_http_client,
        logger=mock_logger,
    )


def _make_response(status_code=200, json_data=None, text="", headers=None):
    """Create a mock httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.text = text or (str(json_data) if json_data else "")
    response.headers = headers or {}
    if json_data is not None:
        response.json.return_value = json_data
    else:
        response.json.side_effect = ValueError("No JSON")
    return response


class TestAuthenticationTests:
    """Tests for _test_authentication method."""

    @pytest.mark.asyncio
    async def test_no_auth_returns_finding_when_not_401_403(self, analyzer, mock_http_client):
        """Endpoint that doesn't return 401/403 without creds should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={"data": "open"})
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        auth_findings = [f for f in findings if f.check == "missing-auth-enforcement"]
        assert len(auth_findings) >= 1
        assert auth_findings[0].category == "authentication"

    @pytest.mark.asyncio
    async def test_no_auth_no_finding_when_401(self, analyzer, mock_http_client):
        """Endpoint returning 401 without creds should not produce auth finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=401)
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        auth_findings = [f for f in findings if f.check == "missing-auth-enforcement"]
        assert len(auth_findings) == 0

    @pytest.mark.asyncio
    async def test_expired_token_finding(self, analyzer, mock_http_client):
        """Endpoint accepting expired token should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={})
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        expired_findings = [f for f in findings if f.check == "expired-token-accepted"]
        assert len(expired_findings) >= 1

    @pytest.mark.asyncio
    async def test_malformed_token_finding(self, analyzer, mock_http_client):
        """Endpoint accepting malformed token should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={})
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        malformed_findings = [f for f in findings if f.check == "malformed-token-accepted"]
        assert len(malformed_findings) >= 1

    @pytest.mark.asyncio
    async def test_invalid_signature_finding(self, analyzer, mock_http_client):
        """Endpoint accepting invalid signature token should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={})
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        sig_findings = [f for f in findings if f.check == "invalid-signature-accepted"]
        assert len(sig_findings) >= 1

    @pytest.mark.asyncio
    async def test_bola_finding(self, analyzer, mock_http_client):
        """Endpoint allowing access to other user's resources should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={"user": "admin"})
        )

        findings = await analyzer._test_authentication("http://api.example.com")

        bola_findings = [f for f in findings if f.check == "bola-vulnerability"]
        assert len(bola_findings) >= 1


class TestResponseIntegrity:
    """Tests for _test_response_integrity method."""

    @pytest.mark.asyncio
    async def test_stack_trace_detection(self, analyzer, mock_http_client):
        """Error response with stack trace should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(
                status_code=500,
                text="Traceback (most recent call last):\n  File \"app.py\", line 42",
            )
        )

        findings = await analyzer._test_response_integrity("http://api.example.com")

        trace_findings = [f for f in findings if f.check == "stack-trace-exposure"]
        assert len(trace_findings) >= 1

    @pytest.mark.asyncio
    async def test_status_code_mismatch_error_body_with_2xx(self, analyzer, mock_http_client):
        """2xx response with error body should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(
                status_code=200,
                json_data={"error": "something went wrong", "error_code": 500},
            )
        )

        findings = await analyzer._test_response_integrity("http://api.example.com")

        mismatch_findings = [f for f in findings if f.check == "status-code-mismatch"]
        assert len(mismatch_findings) >= 1

    @pytest.mark.asyncio
    async def test_sensitive_field_exposure(self, analyzer, mock_http_client):
        """Response with sensitive fields should produce finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(
                status_code=200,
                json_data={"user": "john", "password": "secret123", "token": "abc"},
            )
        )

        findings = await analyzer._test_response_integrity("http://api.example.com")

        sensitive_findings = [f for f in findings if f.check == "sensitive-field-exposure"]
        assert len(sensitive_findings) >= 2  # password and token


class TestSchemaConformance:
    """Tests for _test_schema_conformance method."""

    @pytest.mark.asyncio
    async def test_type_mismatch_detection(self, analyzer, mock_http_client):
        """Different types across responses should produce finding."""
        responses = [
            _make_response(status_code=200, json_data={"name": "Alice", "age": 30}),
            _make_response(status_code=200, json_data={"name": "Bob", "age": 25}),
            _make_response(status_code=200, json_data={"name": 123, "age": 28}),
        ]
        mock_http_client.get = AsyncMock(side_effect=responses)

        findings = await analyzer._test_schema_conformance("http://api.example.com")

        type_findings = [f for f in findings if f.check == "schema-type-mismatch"]
        assert len(type_findings) >= 1

    @pytest.mark.asyncio
    async def test_unexpected_null_detection(self, analyzer, mock_http_client):
        """Null in previously non-null field should produce finding."""
        responses = [
            _make_response(status_code=200, json_data={"name": "Alice", "email": "a@b.com"}),
            _make_response(status_code=200, json_data={"name": "Bob", "email": "b@c.com"}),
            _make_response(status_code=200, json_data={"name": "Charlie", "email": None}),
        ]
        mock_http_client.get = AsyncMock(side_effect=responses)

        findings = await analyzer._test_schema_conformance("http://api.example.com")

        null_findings = [f for f in findings if f.check == "unexpected-null"]
        assert len(null_findings) >= 1

    @pytest.mark.asyncio
    async def test_insufficient_responses(self, analyzer, mock_http_client):
        """Less than 2 responses should produce no findings."""
        mock_http_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        findings = await analyzer._test_schema_conformance("http://api.example.com")

        assert len(findings) == 0


class TestInjection:
    """Tests for _test_injection method."""

    @pytest.mark.asyncio
    async def test_sql_injection_error_detection(self, analyzer, mock_http_client):
        """SQL error in response should produce injection finding."""
        # First call is baseline, subsequent calls return SQL error
        baseline_response = _make_response(status_code=200, text="OK")
        error_response = _make_response(
            status_code=500,
            text="Error: mysql syntax error near 'OR 1=1'",
        )
        mock_http_client.get = AsyncMock(
            side_effect=[baseline_response] + [error_response] * 20
        )

        findings = await analyzer._test_injection("http://api.example.com")

        sql_findings = [f for f in findings if "sql" in f.check]
        assert len(sql_findings) >= 1

    @pytest.mark.asyncio
    async def test_no_injection_when_endpoint_unreachable(self, analyzer, mock_http_client):
        """Unreachable endpoint should return empty findings."""
        mock_http_client.get = AsyncMock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        findings = await analyzer._test_injection("http://api.example.com")

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_payloads_per_category(self, analyzer):
        """Each injection category should have at least 5 payloads."""
        assert len(APIAnalyzer._SQL_PAYLOADS) >= 5
        assert len(APIAnalyzer._NOSQL_PAYLOADS) >= 5
        assert len(APIAnalyzer._CMD_PAYLOADS) >= 5


class TestRateLimiting:
    """Tests for _test_rate_limiting method."""

    @pytest.mark.asyncio
    async def test_missing_rate_limiting_finding(self, analyzer, mock_http_client):
        """No 429 response should produce missing rate limiting finding."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, text="OK")
        )

        config = AnalysisConfig(rate_limit_burst=5, rate_limit_window=1)
        findings = await analyzer._test_rate_limiting("http://api.example.com", config)

        rate_findings = [f for f in findings if f.check == "missing-rate-limiting"]
        assert len(rate_findings) == 1

    @pytest.mark.asyncio
    async def test_rate_limiting_without_retry_after(self, analyzer, mock_http_client):
        """429 without Retry-After header should produce finding."""
        responses = [_make_response(status_code=200)] * 3 + [
            _make_response(status_code=429, headers={})
        ]
        mock_http_client.get = AsyncMock(side_effect=responses)

        config = AnalysisConfig(rate_limit_burst=5, rate_limit_window=1)
        findings = await analyzer._test_rate_limiting("http://api.example.com", config)

        retry_findings = [f for f in findings if f.check == "missing-retry-after-header"]
        assert len(retry_findings) == 1

    @pytest.mark.asyncio
    async def test_rate_limiting_with_retry_after_no_finding(self, analyzer, mock_http_client):
        """429 with Retry-After header should produce no findings."""
        responses = [_make_response(status_code=200)] * 3 + [
            _make_response(status_code=429, headers={"retry-after": "60"})
        ]
        mock_http_client.get = AsyncMock(side_effect=responses)

        config = AnalysisConfig(rate_limit_burst=5, rate_limit_window=1)
        findings = await analyzer._test_rate_limiting("http://api.example.com", config)

        assert len(findings) == 0


class TestAnalyzeOrchestration:
    """Tests for the main analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_returns_analysis_result(self, analyzer, mock_http_client, mock_ai_engine):
        """analyze() should return a complete AnalysisResult."""
        # All requests return 401 (proper auth enforcement)
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=401)
        )
        mock_ai_engine.process_findings.return_value = []

        config = AnalysisConfig(
            timeout=30, rate_limit_burst=5, rate_limit_window=1
        )
        result = await analyzer.analyze("http://api.example.com", config)

        assert result.score == 100
        assert result.grade == "A"
        assert result.metadata.mode == AnalysisMode.API
        assert result.metadata.target == "http://api.example.com"

    @pytest.mark.asyncio
    async def test_analyze_handles_timeout(self, analyzer, mock_http_client, mock_ai_engine):
        """analyze() should handle timeouts gracefully."""
        async def slow_request(*args, **kwargs):
            await asyncio.sleep(100)
            return _make_response(status_code=200)

        mock_http_client.get = slow_request
        mock_ai_engine.process_findings.return_value = []

        config = AnalysisConfig(timeout=1, rate_limit_burst=5, rate_limit_window=1)
        result = await analyzer.analyze("http://api.example.com", config)

        # Should complete without raising, with timeout findings
        assert result is not None
        assert result.metadata.mode == AnalysisMode.API

    @pytest.mark.asyncio
    async def test_analyze_processes_findings_through_ai(self, analyzer, mock_http_client, mock_ai_engine):
        """analyze() should pass findings to AI engine."""
        mock_http_client.get = AsyncMock(
            return_value=_make_response(status_code=200, json_data={"password": "secret"})
        )
        mock_ai_engine.process_findings.return_value = [
            Issue(
                check="sensitive-field-exposure",
                severity=Severity.HIGH,
                title="Sensitive field exposed",
                description="Password field in response",
                evidence="Field 'password' found",
                recommendation="Remove sensitive fields",
            )
        ]

        config = AnalysisConfig(
            timeout=30, rate_limit_burst=5, rate_limit_window=1
        )
        result = await analyzer.analyze("http://api.example.com", config)

        mock_ai_engine.process_findings.assert_called_once()
        assert len(result.issues) == 1
        assert result.issues[0].severity == Severity.HIGH

