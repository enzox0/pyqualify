"""Data models for PyQualify analysis tool."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Classification level for issues."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalysisMode(str, Enum):
    """Analysis mode indicating the type of target being analyzed."""

    WEB = "web"
    CODE = "code"
    API = "api"


class RiskLevel(str, Enum):
    """Overall risk classification derived from analysis findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class BugRiskType(str, Enum):
    """Categories of bug risk detected in code analysis."""

    NULL_DEREFERENCE = "null-dereference"
    UNCAUGHT_EXCEPTION = "uncaught-exception"
    RACE_CONDITION = "race-condition"
    OFF_BY_ONE = "off-by-one"


@dataclass
class RawFinding:
    """A raw finding produced by an analyzer before AI enrichment."""

    check: str
    category: str
    location: str
    evidence: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class Issue:
    """A fully enriched issue after AI processing."""

    check: str
    severity: Severity
    title: str  # max 120 chars
    description: str  # max 1000 chars
    evidence: str  # max 2000 chars
    recommendation: str  # max 500 chars
    cwe: str | None = None
    owasp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dict."""
        return {
            "check": self.check,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "owasp": self.owasp,
        }


@dataclass
class AnalysisMetadata:
    """Metadata about the analysis run."""

    timestamp: str  # ISO 8601
    target: str
    mode: AnalysisMode

    def to_dict(self) -> dict[str, str]:
        """Serialize to JSON-compatible dict."""
        return {
            "timestamp": self.timestamp,
            "target": self.target,
            "mode": self.mode.value,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result with scoring."""

    score: int  # 0-100
    grade: str  # A-F
    risk_level: RiskLevel
    issues: list[Issue]
    summary: str  # max 500 chars
    metadata: AnalysisMetadata

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the canonical JSON output structure."""
        return {
            "score": self.score,
            "grade": self.grade,
            "risk_level": self.risk_level.value,
            "issues": [issue.to_dict() for issue in self.issues],
            "summary": self.summary,
            "metadata": self.metadata.to_dict(),
        }


@dataclass
class AnalysisConfig:
    """Configuration for an analysis run."""

    timeout: int = 30
    max_links: int = 500
    rate_limit_burst: int = 50
    rate_limit_window: int = 10
    html_output: str | None = None
    json_output: bool = False


@dataclass
class AIConfig:
    """Configuration for the AI Engine."""

    api_key: str
    provider: str = "openai"          # openai | anthropic | google
    base_url: str = ""                 # auto-set per provider if empty
    model: str = ""                    # auto-set per provider if empty
    timeout: int = 60
    max_retries: int = 3
    retry_delay: float = 2.0


@dataclass
class LogConfig:
    """Configuration for the logging system."""

    level: str = "INFO"
    log_file: str | None = None


@dataclass
class AnalysisContext:
    """Context passed to AI Engine for prompt construction."""

    mode: AnalysisMode
    target: str
    additional_context: dict[str, Any] = field(default_factory=dict)
