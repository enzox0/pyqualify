"""Prompt manager for constructing structured LLM prompts."""

from pyqualify.models import RawFinding


# Shared JSON schema instruction included in all prompts
_ISSUE_SCHEMA_INSTRUCTION = """\
You MUST respond with a JSON object containing a single key "issues" whose value is an array.
Each element in the array MUST be a JSON object with the following fields:

- "check": (string) A short kebab-case identifier for the check (e.g., "missing-csp-header").
- "severity": (string) Exactly one of: "critical", "high", "medium", "low", "info".
- "title": (string) A concise title describing the issue. Maximum 200 characters.
- "description": (string) A detailed explanation of the issue and its impact. Maximum 2000 characters.
- "evidence": (string) The observed evidence that triggered this finding. Maximum 2000 characters.
- "recommendation": (string) Actionable remediation steps. Maximum 2000 characters.
- "cwe": (string or null) The CWE identifier if the issue maps to a known weakness (e.g., "CWE-79"). Null if not applicable.
- "owasp": (string or null) The OWASP Top 10 reference if applicable (e.g., "A03:2021"). Null if not applicable.

Severity classification guidelines:
- CRITICAL: Exploitable vulnerabilities with immediate risk of data breach or system compromise.
- HIGH: Serious security weaknesses or failures that require urgent attention.
- MEDIUM: Moderate issues that should be addressed but pose limited immediate risk.
- LOW: Minor issues or best-practice deviations with minimal security impact.
- INFO: Informational observations or suggestions for improvement.

Return ONLY valid JSON. Do not include markdown formatting, code fences, or explanatory text outside the JSON object."""


def _format_findings(findings: list[RawFinding]) -> str:
    """Format raw findings into a readable text block for the prompt."""
    if not findings:
        return "No raw findings provided."

    lines: list[str] = []
    for i, finding in enumerate(findings, start=1):
        lines.append(f"Finding {i}:")
        lines.append(f"  Check: {finding.check}")
        lines.append(f"  Category: {finding.category}")
        lines.append(f"  Location: {finding.location}")
        lines.append(f"  Evidence: {finding.evidence}")
        if finding.context:
            context_items = ", ".join(
                f"{k}={v}" for k, v in finding.context.items()
            )
            lines.append(f"  Context: {context_items}")
        lines.append("")

    return "\n".join(lines)


class PromptManager:
    """Manages structured prompts for different analysis contexts."""

    def build_web_prompt(self, findings: list[RawFinding], url: str) -> str:
        """Build a prompt for web analysis findings.

        Args:
            findings: Raw findings from the web analyzer.
            url: The target URL that was analyzed.

        Returns:
            A structured prompt string requesting JSON-formatted issues.
        """
        findings_text = _format_findings(findings)

        return f"""\
You are a security and quality analyst specializing in web application analysis.

Analysis Mode: WEB
Target: {url}

You are reviewing findings from an automated web analysis of the target URL above.
The analysis checked security headers, form security (CSRF), SEO elements, accessibility compliance, performance signals, link integrity, CAPTCHA presence, HTTP request smuggling indicators, case-sensitivity access controls, JSON hijacking vectors, open redirect parameters, server version/technology disclosure in headers, and DOM-based XSS sinks.

Your task is to classify and enrich the following raw findings into structured issues with severity ratings, descriptions, evidence, and actionable recommendations.

Raw Findings:
{findings_text}

{_ISSUE_SCHEMA_INSTRUCTION}"""

    def build_code_prompt(self, findings: list[RawFinding], filepath: str) -> str:
        """Build a prompt for code analysis findings.

        Args:
            findings: Raw findings from the code analyzer.
            filepath: The file or directory path that was analyzed.

        Returns:
            A structured prompt string requesting JSON-formatted issues.
        """
        findings_text = _format_findings(findings)

        return f"""\
You are a security and quality analyst specializing in source code review.

Analysis Mode: CODE
Target: {filepath}

You are reviewing findings from an automated code analysis of the target path above.
The analysis checked for security vulnerabilities (injection, hardcoded secrets, insecure deserialization, path traversal), bug risks (null dereferences, uncaught exceptions, race conditions, off-by-one errors), code quality (dead code, duplication, complexity, magic numbers), test coverage gaps, dependency risks (typosquatting, deprecated packages, wildcard imports), known CVE-affected packages, weak or missing password policy enforcement, audit log manipulation patterns, and case-sensitivity issues in auth/routing comparisons.

Your task is to classify and enrich the following raw findings into structured issues with severity ratings, descriptions, evidence, and actionable recommendations. Include code-specific context such as file paths and line numbers in your evidence and recommendations.

Raw Findings:
{findings_text}

{_ISSUE_SCHEMA_INSTRUCTION}"""

    def build_api_prompt(self, findings: list[RawFinding], endpoint: str) -> str:
        """Build a prompt for API analysis findings.

        Args:
            findings: Raw findings from the API analyzer.
            endpoint: The API base URL or endpoint that was analyzed.

        Returns:
            A structured prompt string requesting JSON-formatted issues.
        """
        findings_text = _format_findings(findings)

        return f"""\
You are a security and quality analyst specializing in REST API security testing.

Analysis Mode: API
Target: {endpoint}

You are reviewing findings from an automated API security analysis of the target endpoint above.
The analysis tested authentication enforcement, response integrity (information leakage, status code mismatches), schema conformance, injection vulnerabilities (SQL, NoSQL, command injection), rate limiting, audit log manipulation, CAPTCHA bypass, HTTP request smuggling, case-sensitivity route bypass, JSON hijacking, open redirect via query parameters, server version/technology disclosure in headers, internal IP and domain leakage in response bodies, and application-level DoS vectors (missing payload size limits, JSON depth limits).

Your task is to classify and enrich the following raw findings into structured issues with severity ratings, descriptions, evidence, and actionable recommendations. Include endpoint paths and HTTP details in your evidence.

Raw Findings:
{findings_text}

{_ISSUE_SCHEMA_INSTRUCTION}"""
