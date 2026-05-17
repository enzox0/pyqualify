"""Unit tests for the WebAnalyzer."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from pyqualify.analyzers.web_analyzer import WebAnalyzer
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMode,
    Issue,
    LogConfig,
    RawFinding,
    RiskLevel,
    Severity,
)


@pytest.fixture
def logger():
    """Create a test logger."""
    return PyqualifyLogger(LogConfig(level="ERROR"))


@pytest.fixture
def mock_ai_engine():
    """Create a mock AI engine that returns issues from findings."""
    engine = AsyncMock()

    async def process_findings(findings, context):
        # Convert findings to simple issues for testing
        issues = []
        for f in findings:
            severity_hint = f.context.get("severity_hint", "info")
            issues.append(Issue(
                check=f.check,
                severity=Severity(severity_hint),
                title=f"Issue: {f.check}",
                description=f.evidence,
                evidence=f.evidence,
                recommendation="Fix this issue",
            ))
        return issues

    engine.process_findings = AsyncMock(side_effect=process_findings)
    return engine


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client."""
    client = AsyncMock(spec=httpx.AsyncClient)
    return client


def make_response(
    status_code: int = 200,
    headers: dict | None = None,
    text: str = "<html><head><title>Test</title></head><body></body></html>",
    url: str = "https://example.com",
) -> MagicMock:
    """Create a mock httpx.Response."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status_code
    response.headers = httpx.Headers(headers or {})
    response.text = text
    response.url = httpx.URL(url)
    return response


class TestSecurityHeaders:
    """Tests for _check_security_headers."""

    @pytest.mark.asyncio
    async def test_missing_all_security_headers(self, mock_ai_engine, logger):
        """All security headers missing should produce findings."""
        response = make_response(headers={})
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_security_headers(response)

        assert len(findings) == 5
        checks = {f.check for f in findings}
        assert "missing-content-security-policy-header" in checks
        assert "missing-strict-transport-security-header" in checks
        assert "missing-x-frame-options-header" in checks
        assert "missing-referrer-policy-header" in checks
        assert "missing-permissions-policy-header" in checks

    @pytest.mark.asyncio
    async def test_all_headers_present_and_secure(self, mock_ai_engine, logger):
        """All headers present with secure values should produce no findings."""
        response = make_response(headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
        })
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_security_headers(response)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_hsts_low_max_age(self, mock_ai_engine, logger):
        """HSTS with low max-age should produce a misconfiguration finding."""
        response = make_response(headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=3600",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        })
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_security_headers(response)

        assert len(findings) == 1
        assert findings[0].check == "misconfigured-strict-transport-security-header"
        assert "3600" in findings[0].evidence

    @pytest.mark.asyncio
    async def test_csp_unsafe_inline(self, mock_ai_engine, logger):
        """CSP with unsafe-inline should produce a misconfiguration finding."""
        response = make_response(headers={
            "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        })
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_security_headers(response)

        assert len(findings) == 1
        assert findings[0].check == "misconfigured-content-security-policy-header"
        assert "unsafe-inline" in findings[0].evidence


class TestFormChecks:
    """Tests for _check_forms."""

    @pytest.mark.asyncio
    async def test_post_form_without_csrf(self, mock_ai_engine, logger):
        """POST form without CSRF token should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><form method="POST" action="/login">'
            '<input type="text" name="username">'
            '<input type="password" name="password">'
            "</form></body></html>",
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_forms(html)

        csrf_findings = [f for f in findings if f.check == "missing-csrf-token"]
        assert len(csrf_findings) == 1
        assert "POST" in csrf_findings[0].evidence

    @pytest.mark.asyncio
    async def test_post_form_with_csrf_token(self, mock_ai_engine, logger):
        """POST form with CSRF token should not produce a CSRF finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><form method="POST" action="/login">'
            '<input type="hidden" name="csrf_token" value="abc123">'
            '<input type="text" name="username">'
            "</form></body></html>",
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_forms(html)

        csrf_findings = [f for f in findings if f.check == "missing-csrf-token"]
        assert len(csrf_findings) == 0

    @pytest.mark.asyncio
    async def test_get_form_skips_csrf_check(self, mock_ai_engine, logger):
        """GET form should not be checked for CSRF tokens."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><form method="GET" action="/search">'
            '<input type="text" name="q">'
            "</form></body></html>",
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_forms(html)

        csrf_findings = [f for f in findings if f.check == "missing-csrf-token"]
        assert len(csrf_findings) == 0

    @pytest.mark.asyncio
    async def test_sensitive_autocomplete_enabled(self, mock_ai_engine, logger):
        """Sensitive input with autocomplete enabled should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><form method="POST" action="/pay">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '<input type="text" name="cc-number" autocomplete="cc-number">'
            "</form></body></html>",
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_forms(html)

        autocomplete_findings = [
            f for f in findings if f.check == "sensitive-autocomplete-enabled"
        ]
        assert len(autocomplete_findings) == 1


class TestSEOChecks:
    """Tests for _check_seo."""

    @pytest.mark.asyncio
    async def test_missing_all_seo_elements(self, mock_ai_engine, logger):
        """Page with no SEO elements should produce findings for all."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup("<html><head></head><body></body></html>", "lxml")
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_seo(html)

        checks = {f.check for f in findings}
        assert "missing-title-tag" in checks
        assert "missing-meta-description" in checks
        assert "missing-canonical-link" in checks
        assert "missing-og-title-tag" in checks
        assert "missing-og-description-tag" in checks
        assert "missing-og-image-tag" in checks
        assert "missing-og-url-tag" in checks
        assert "missing-robots-meta" in checks

    @pytest.mark.asyncio
    async def test_complete_seo_elements(self, mock_ai_engine, logger):
        """Page with all SEO elements should produce no findings."""
        from bs4 import BeautifulSoup

        html_str = (
            '<html><head>'
            '<title>Test Page</title>'
            '<meta name="description" content="A test page">'
            '<link rel="canonical" href="https://example.com">'
            '<meta property="og:title" content="Test">'
            '<meta property="og:description" content="Desc">'
            '<meta property="og:image" content="img.png">'
            '<meta property="og:url" content="https://example.com">'
            '<meta name="robots" content="index, follow">'
            '</head><body></body></html>'
        )
        html = BeautifulSoup(html_str, "lxml")
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_seo(html)

        assert len(findings) == 0


class TestAccessibilityChecks:
    """Tests for _check_accessibility."""

    @pytest.mark.asyncio
    async def test_missing_alt_attribute(self, mock_ai_engine, logger):
        """Image without alt attribute should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html lang="en"><body><img src="photo.jpg"></body></html>', "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_accessibility(html)

        alt_findings = [f for f in findings if f.check == "missing-alt-attribute"]
        assert len(alt_findings) == 1

    @pytest.mark.asyncio
    async def test_heading_hierarchy_skip(self, mock_ai_engine, logger):
        """Heading skip (h1 to h3) should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html lang="en"><body><h1>Title</h1><h3>Subtitle</h3></body></html>',
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_accessibility(html)

        heading_findings = [
            f for f in findings if f.check == "heading-hierarchy-skip"
        ]
        assert len(heading_findings) == 1
        assert "h1" in heading_findings[0].evidence
        assert "h3" in heading_findings[0].evidence

    @pytest.mark.asyncio
    async def test_missing_lang_attribute(self, mock_ai_engine, logger):
        """HTML without lang attribute should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            "<html><body><p>Hello</p></body></html>", "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_accessibility(html)

        lang_findings = [f for f in findings if f.check == "missing-lang-attribute"]
        assert len(lang_findings) == 1

    @pytest.mark.asyncio
    async def test_missing_form_label(self, mock_ai_engine, logger):
        """Input without label should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html lang="en"><body>'
            '<input type="text" name="email">'
            "</body></html>",
            "lxml",
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_accessibility(html)

        label_findings = [f for f in findings if f.check == "missing-form-label"]
        assert len(label_findings) == 1


class TestPerformanceChecks:
    """Tests for _check_performance."""

    @pytest.mark.asyncio
    async def test_large_inline_script(self, mock_ai_engine, logger):
        """Inline script >1KB should produce a finding."""
        from bs4 import BeautifulSoup

        large_script = "var x = 'a';\n" * 200  # Well over 1KB
        html = BeautifulSoup(
            f"<html><body><script>{large_script}</script></body></html>", "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_performance(html, load_time=1.0)

        script_findings = [f for f in findings if f.check == "large-inline-script"]
        assert len(script_findings) == 1

    @pytest.mark.asyncio
    async def test_slow_dom_content_loaded(self, mock_ai_engine, logger):
        """Load time >3s should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup("<html><body></body></html>", "lxml")
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_performance(html, load_time=4.5)

        slow_findings = [f for f in findings if f.check == "slow-dom-content-loaded"]
        assert len(slow_findings) == 1
        assert "4500" in slow_findings[0].evidence

    @pytest.mark.asyncio
    async def test_fast_load_no_finding(self, mock_ai_engine, logger):
        """Load time <3s should not produce a DOMContentLoaded finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup("<html><body></body></html>", "lxml")
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_performance(html, load_time=1.5)

        slow_findings = [f for f in findings if f.check == "slow-dom-content-loaded"]
        assert len(slow_findings) == 0


class TestLinkChecks:
    """Tests for _check_links."""

    @pytest.mark.asyncio
    async def test_broken_link_4xx(self, mock_ai_engine, logger):
        """Link returning 404 should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><a href="/broken">Link</a></body></html>', "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        resp_404 = MagicMock()
        resp_404.status_code = 404
        client.head = AsyncMock(return_value=resp_404)

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_links(html, "https://example.com")

        broken_findings = [f for f in findings if f.check == "broken-link-4xx"]
        assert len(broken_findings) == 1
        assert "404" in broken_findings[0].evidence

    @pytest.mark.asyncio
    async def test_broken_link_5xx(self, mock_ai_engine, logger):
        """Link returning 500 should produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><a href="/error">Link</a></body></html>', "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        resp_500 = MagicMock()
        resp_500.status_code = 500
        client.head = AsyncMock(return_value=resp_500)

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_links(html, "https://example.com")

        broken_findings = [f for f in findings if f.check == "broken-link-5xx"]
        assert len(broken_findings) == 1
        assert "500" in broken_findings[0].evidence

    @pytest.mark.asyncio
    async def test_successful_link_no_finding(self, mock_ai_engine, logger):
        """Link returning 200 should not produce a finding."""
        from bs4 import BeautifulSoup

        html = BeautifulSoup(
            '<html><body><a href="/ok">Link</a></body></html>', "lxml"
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        resp_200 = MagicMock()
        resp_200.status_code = 200
        client.head = AsyncMock(return_value=resp_200)

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        findings = await analyzer._check_links(html, "https://example.com")

        # Should have no broken link findings (suspicious domain check may still run)
        broken_findings = [
            f for f in findings
            if f.check in ("broken-link-4xx", "broken-link-5xx", "link-timeout")
        ]
        assert len(broken_findings) == 0


class TestSuspiciousDomains:
    """Tests for _check_suspicious_domain."""

    def test_legitimate_domain(self, mock_ai_engine, logger):
        """Legitimate domain should not be flagged."""
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        result = analyzer._check_suspicious_domain("https://google.com/search")
        assert result is None

    def test_homoglyph_domain(self, mock_ai_engine, logger):
        """Domain with homoglyph substitution should be flagged."""
        client = AsyncMock(spec=httpx.AsyncClient)
        analyzer = WebAnalyzer(mock_ai_engine, client, logger)

        # Use Cyrillic 'Ð¾' (U+043E) instead of Latin 'o'
        result = analyzer._check_suspicious_domain("https://g\u043e\u043egle.com")
        assert result is not None
        assert "google" in result


class TestAnalyzeMethod:
    """Tests for the main analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_unreachable_url(self, mock_ai_engine, logger):
        """Unreachable URL should still return a result with findings."""
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)
        config = AnalysisConfig()

        result = await analyzer.analyze("https://unreachable.example.com", config)

        assert result.score is not None
        assert result.grade is not None
        assert result.metadata.target == "https://unreachable.example.com"
        assert result.metadata.mode == AnalysisMode.WEB

    @pytest.mark.asyncio
    async def test_analyze_successful_page(self, mock_ai_engine, logger):
        """Successful page analysis should return complete result."""
        html_content = (
            '<html lang="en"><head>'
            '<title>Test Page</title>'
            '<meta name="description" content="A test page">'
            '<link rel="canonical" href="https://example.com">'
            '<meta property="og:title" content="Test">'
            '<meta property="og:description" content="Desc">'
            '<meta property="og:image" content="img.png">'
            '<meta property="og:url" content="https://example.com">'
            '<meta name="robots" content="index, follow">'
            '</head><body><p>Hello</p></body></html>'
        )
        response = make_response(
            status_code=200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=()",
            },
            text=html_content,
        )
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(return_value=response)

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)
        config = AnalysisConfig()

        result = await analyzer.analyze("https://example.com", config)

        assert result.score >= 0
        assert result.score <= 100
        assert result.grade in ("A", "B", "C", "D", "F")
        assert result.risk_level in (
            RiskLevel.CRITICAL, RiskLevel.HIGH,
            RiskLevel.MEDIUM, RiskLevel.LOW,
        )
        assert result.metadata.mode == AnalysisMode.WEB
        assert "example.com" in result.metadata.target

    @pytest.mark.asyncio
    async def test_analyze_non_2xx_response(self, mock_ai_engine, logger):
        """Non-2xx response should produce connectivity finding."""
        response = make_response(status_code=403)
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(return_value=response)

        analyzer = WebAnalyzer(mock_ai_engine, client, logger)
        config = AnalysisConfig()

        result = await analyzer.analyze("https://example.com", config)

        # Should have processed the non-2xx finding
        mock_ai_engine.process_findings.assert_called_once()
        call_findings = mock_ai_engine.process_findings.call_args[0][0]
        non_2xx = [f for f in call_findings if f.check == "non-2xx-response"]
        assert len(non_2xx) == 1

