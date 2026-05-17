"""Tests for qaai.models data models."""

from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    AIConfig,
    BugRiskType,
    Issue,
    LogConfig,
    RawFinding,
    RiskLevel,
    Severity,
)


class TestEnums:
    """Tests for enum definitions."""

    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_severity_is_str_enum(self):
        assert isinstance(Severity.CRITICAL, str)
        assert Severity.CRITICAL.value == "critical"

    def test_analysis_mode_values(self):
        assert AnalysisMode.WEB == "web"
        assert AnalysisMode.CODE == "code"
        assert AnalysisMode.API == "api"

    def test_analysis_mode_is_str_enum(self):
        assert isinstance(AnalysisMode.WEB, str)

    def test_risk_level_values(self):
        assert RiskLevel.CRITICAL == "critical"
        assert RiskLevel.HIGH == "high"
        assert RiskLevel.MEDIUM == "medium"
        assert RiskLevel.LOW == "low"

    def test_bug_risk_type_values(self):
        assert BugRiskType.NULL_DEREFERENCE == "null-dereference"
        assert BugRiskType.UNCAUGHT_EXCEPTION == "uncaught-exception"
        assert BugRiskType.RACE_CONDITION == "race-condition"
        assert BugRiskType.OFF_BY_ONE == "off-by-one"


class TestRawFinding:
    """Tests for RawFinding dataclass."""

    def test_creation_with_required_fields(self):
        finding = RawFinding(
            check="missing-csp",
            category="security",
            location="https://example.com",
            evidence="No CSP header found",
        )
        assert finding.check == "missing-csp"
        assert finding.category == "security"
        assert finding.location == "https://example.com"
        assert finding.evidence == "No CSP header found"
        assert finding.context == {}

    def test_creation_with_context(self):
        finding = RawFinding(
            check="missing-csp",
            category="security",
            location="https://example.com",
            evidence="No CSP header found",
            context={"headers": {"X-Frame-Options": "DENY"}},
        )
        assert finding.context == {"headers": {"X-Frame-Options": "DENY"}}

    def test_default_context_is_independent(self):
        f1 = RawFinding(check="a", category="b", location="c", evidence="d")
        f2 = RawFinding(check="a", category="b", location="c", evidence="d")
        f1.context["key"] = "value"
        assert f2.context == {}


class TestIssue:
    """Tests for Issue dataclass and to_dict()."""

    def _make_issue(self, **kwargs) -> Issue:
        defaults = {
            "check": "missing-csp-header",
            "severity": Severity.HIGH,
            "title": "Missing Content-Security-Policy Header",
            "description": "The server does not include a CSP header.",
            "evidence": "Response headers: {}",
            "recommendation": "Add CSP header with restrictive directives.",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        }
        defaults.update(kwargs)
        return Issue(**defaults)

    def test_creation(self):
        issue = self._make_issue()
        assert issue.check == "missing-csp-header"
        assert issue.severity == Severity.HIGH
        assert issue.cwe == "CWE-693"
        assert issue.owasp == "A05:2021"

    def test_optional_fields_default_none(self):
        issue = Issue(
            check="test",
            severity=Severity.LOW,
            title="Test",
            description="Desc",
            evidence="Ev",
            recommendation="Rec",
        )
        assert issue.cwe is None
        assert issue.owasp is None

    def test_to_dict(self):
        issue = self._make_issue()
        result = issue.to_dict()
        assert result == {
            "check": "missing-csp-header",
            "severity": "high",
            "title": "Missing Content-Security-Policy Header",
            "description": "The server does not include a CSP header.",
            "evidence": "Response headers: {}",
            "recommendation": "Add CSP header with restrictive directives.",
            "cwe": "CWE-693",
            "owasp": "A05:2021",
        }

    def test_to_dict_with_none_optional_fields(self):
        issue = self._make_issue(cwe=None, owasp=None)
        result = issue.to_dict()
        assert result["cwe"] is None
        assert result["owasp"] is None

    def test_to_dict_severity_is_string_value(self):
        issue = self._make_issue(severity=Severity.CRITICAL)
        result = issue.to_dict()
        assert result["severity"] == "critical"
        assert isinstance(result["severity"], str)


class TestAnalysisMetadata:
    """Tests for AnalysisMetadata dataclass and to_dict()."""

    def test_creation(self):
        meta = AnalysisMetadata(
            timestamp="2024-01-15T10:30:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        )
        assert meta.timestamp == "2024-01-15T10:30:00Z"
        assert meta.target == "https://example.com"
        assert meta.mode == AnalysisMode.WEB

    def test_to_dict(self):
        meta = AnalysisMetadata(
            timestamp="2024-01-15T10:30:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        )
        result = meta.to_dict()
        assert result == {
            "timestamp": "2024-01-15T10:30:00Z",
            "target": "https://example.com",
            "mode": "web",
        }

    def test_to_dict_mode_is_string_value(self):
        meta = AnalysisMetadata(
            timestamp="2024-01-15T10:30:00Z",
            target="/path/to/code",
            mode=AnalysisMode.CODE,
        )
        result = meta.to_dict()
        assert result["mode"] == "code"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass and to_dict()."""

    def _make_result(self, **kwargs) -> AnalysisResult:
        defaults = {
            "score": 72,
            "grade": "C",
            "risk_level": RiskLevel.HIGH,
            "issues": [
                Issue(
                    check="missing-csp-header",
                    severity=Severity.HIGH,
                    title="Missing CSP Header",
                    description="No CSP header found.",
                    evidence="Response headers: {}",
                    recommendation="Add CSP header.",
                    cwe="CWE-693",
                    owasp="A05:2021",
                )
            ],
            "summary": "Analysis found 1 issue.",
            "metadata": AnalysisMetadata(
                timestamp="2024-01-15T10:30:00Z",
                target="https://example.com",
                mode=AnalysisMode.WEB,
            ),
        }
        defaults.update(kwargs)
        return AnalysisResult(**defaults)

    def test_creation(self):
        result = self._make_result()
        assert result.score == 72
        assert result.grade == "C"
        assert result.risk_level == RiskLevel.HIGH
        assert len(result.issues) == 1
        assert result.summary == "Analysis found 1 issue."

    def test_to_dict_canonical_structure(self):
        result = self._make_result()
        d = result.to_dict()
        assert d["score"] == 72
        assert d["grade"] == "C"
        assert d["risk_level"] == "high"
        assert isinstance(d["issues"], list)
        assert len(d["issues"]) == 1
        assert d["issues"][0]["check"] == "missing-csp-header"
        assert d["issues"][0]["severity"] == "high"
        assert d["summary"] == "Analysis found 1 issue."
        assert d["metadata"] == {
            "timestamp": "2024-01-15T10:30:00Z",
            "target": "https://example.com",
            "mode": "web",
        }

    def test_to_dict_empty_issues(self):
        result = self._make_result(issues=[])
        d = result.to_dict()
        assert d["issues"] == []

    def test_to_dict_multiple_issues(self):
        issues = [
            Issue(
                check="check-1",
                severity=Severity.CRITICAL,
                title="Critical Issue",
                description="Desc",
                evidence="Ev",
                recommendation="Rec",
            ),
            Issue(
                check="check-2",
                severity=Severity.LOW,
                title="Low Issue",
                description="Desc",
                evidence="Ev",
                recommendation="Rec",
            ),
        ]
        result = self._make_result(issues=issues)
        d = result.to_dict()
        assert len(d["issues"]) == 2
        assert d["issues"][0]["severity"] == "critical"
        assert d["issues"][1]["severity"] == "low"


class TestAnalysisConfig:
    """Tests for AnalysisConfig dataclass."""

    def test_defaults(self):
        config = AnalysisConfig()
        assert config.timeout == 30
        assert config.max_links == 500
        assert config.rate_limit_burst == 50
        assert config.rate_limit_window == 10
        assert config.html_output is None
        assert config.json_output is False

    def test_custom_values(self):
        config = AnalysisConfig(
            timeout=60,
            max_links=100,
            html_output="report.html",
            json_output=True,
        )
        assert config.timeout == 60
        assert config.max_links == 100
        assert config.html_output == "report.html"
        assert config.json_output is True


class TestAIConfig:
    """Tests for AIConfig dataclass."""

    def test_required_api_key(self):
        config = AIConfig(api_key="sk-test-key")
        assert config.api_key == "sk-test-key"
        assert config.base_url == "https://api.openai.com/v1"
        assert config.model == "gpt-4o"
        assert config.timeout == 60
        assert config.max_retries == 3
        assert config.retry_delay == 2.0

    def test_custom_values(self):
        config = AIConfig(
            api_key="sk-custom",
            base_url="https://custom.api.com/v1",
            model="gpt-3.5-turbo",
            timeout=120,
            max_retries=5,
            retry_delay=1.0,
        )
        assert config.base_url == "https://custom.api.com/v1"
        assert config.model == "gpt-3.5-turbo"


class TestLogConfig:
    """Tests for LogConfig dataclass."""

    def test_defaults(self):
        config = LogConfig()
        assert config.level == "INFO"
        assert config.log_file is None

    def test_custom_values(self):
        config = LogConfig(level="DEBUG", log_file="/var/log/qaai.log")
        assert config.level == "DEBUG"
        assert config.log_file == "/var/log/qaai.log"


class TestAnalysisContext:
    """Tests for AnalysisContext dataclass."""

    def test_creation(self):
        ctx = AnalysisContext(
            mode=AnalysisMode.WEB,
            target="https://example.com",
        )
        assert ctx.mode == AnalysisMode.WEB
        assert ctx.target == "https://example.com"
        assert ctx.additional_context == {}

    def test_with_additional_context(self):
        ctx = AnalysisContext(
            mode=AnalysisMode.CODE,
            target="/src/main.py",
            additional_context={"language": "python"},
        )
        assert ctx.additional_context == {"language": "python"}

    def test_default_additional_context_is_independent(self):
        ctx1 = AnalysisContext(mode=AnalysisMode.API, target="/api")
        ctx2 = AnalysisContext(mode=AnalysisMode.API, target="/api")
        ctx1.additional_context["key"] = "value"
        assert ctx2.additional_context == {}

