"""API Analyzer for testing REST API endpoints for security and integrity."""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from pyqualify.ai.protocol import AIEngineProtocol
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    RawFinding,
    RiskLevel,
)
from pyqualify.scoring.engine import ScoringEngine
from pyqualify.tool_registry import ToolSelector
from pyqualify.utils import resolve_location, truncate_evidence


class APIAnalyzer:
    """Analyzes API endpoints for security, integrity, and compliance."""

    _MODULE = "api_analyzer"

    # SQL injection payloads
    _SQL_PAYLOADS = [
        "' OR 1=1--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; DROP TABLE users--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
    ]

    # NoSQL injection payloads
    _NOSQL_PAYLOADS = [
        '{"$gt":""}',
        '{"$ne":null}',
        '{"$regex":".*"}',
        '{"$where":"sleep(5000)"}',
        '{"$or":[{},{"a":"a"}]}',
        '{"$exists":true}',
    ]

    # Command injection payloads
    _CMD_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
        "; sleep 10",
        "| ping -c 5 127.0.0.1",
    ]

    # Sensitive field patterns
    _SENSITIVE_PATTERNS = [
        "password",
        "secret",
        "token",
        "private_key",
        "privatekey",
        "api_key",
        "apikey",
        "ssn",
        "credit_card",
    ]

    # Stack trace / internal info patterns
    _STACK_TRACE_PATTERNS = [
        "Traceback (most recent call last)",
        "at java.",
        "at org.",
        "at com.",
        "Exception in thread",
        "NullPointerException",
        "StackOverflowError",
        "node_modules/",
        "File \"",
        "line \\d+, in",
    ]

    _DB_QUERY_PATTERNS = [
        "SELECT ",
        "INSERT INTO",
        "UPDATE ",
        "DELETE FROM",
        "WHERE ",
        "INNER JOIN",
        "pg_catalog",
        "mysql.",
        "sqlite_master",
    ]

    _FILE_PATH_PATTERNS = [
        "/usr/",
        "/var/",
        "/etc/",
        "C:\\\\",
        "\\\\Users\\\\",
        "/home/",
    ]

    def __init__(
        self,
        ai_engine: AIEngineProtocol,
        http_client: httpx.AsyncClient,
        logger: PyqualifyLogger,
    ) -> None:
        """Initialize the API Analyzer.

        Args:
            ai_engine: AI engine for processing raw findings into enriched issues.
            http_client: Async HTTP client for making requests.
            logger: Centralized logger instance.
        """
        self._ai_engine = ai_engine
        self._http_client = http_client
        self._logger = logger
        self._scoring_engine = ScoringEngine()

    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:
        """Run API analysis on the given base URL.

        Orchestrates all test categories with a 30-second timeout per endpoint.

        Args:
            target: The API base URL to analyze.
            config: Configuration for the analysis run.

        Returns:
            A complete AnalysisResult with score, grade, risk level, and issues.
        """
        self._logger.info(self._MODULE, f"Starting API analysis for: {target}")
        all_findings: list[RawFinding] = []

        endpoint = target.rstrip("/")
        timeout = config.timeout or 30

        # Run each test category with timeout
        # Maps internal test name -> (registry tool name, method)
        test_methods = [
            ("authentication", "authentication", self._test_authentication),
            ("response_integrity", "response-integrity", self._test_response_integrity),
            ("injection", "injection", self._test_injection),
            ("rate_limiting", "rate-limiting", self._test_rate_limiting),
            ("audit_log_manipulation", "audit-log-manipulation", self._test_audit_log_manipulation),
            ("captcha_bypass", "captcha-bypass", self._test_captcha_bypass),
            ("http_request_smuggling", "http-request-smuggling", self._test_http_request_smuggling),
            ("case_sensitivity", "case-sensitivity", self._test_case_sensitivity),
            ("json_hijacking", "json-hijacking", self._test_json_hijacking),
            ("open_redirect", "open-redirect", self._test_open_redirect),
            ("server_version_disclosure", "server-version-disclosure", self._test_server_version_disclosure),
            ("internal_ip_leakage", "internal-ip-leakage", self._test_internal_ip_leakage),
            ("application_dos", "application-dos", self._test_application_dos),
        ]

        # Build tool selector from config
        tool_selector = ToolSelector.from_config("api", config)
        if tool_selector.only or tool_selector.exclude:
            self._logger.info(
                self._MODULE,
                f"Enabled tools: {tool_selector.get_enabled_tools()}",
            )

        for test_name, registry_name, test_method in test_methods:
            # Skip disabled tools
            if not tool_selector.is_enabled(registry_name):
                self._logger.debug(
                    self._MODULE,
                    f"Skipping disabled tool: {registry_name}",
                )
                continue
            try:
                if test_name == "rate_limiting":
                    findings = await asyncio.wait_for(
                        test_method(endpoint, config),
                        timeout=timeout,
                    )
                else:
                    findings = await asyncio.wait_for(
                        test_method(endpoint),
                        timeout=timeout,
                    )
                all_findings.extend(findings)
                self._logger.info(
                    self._MODULE,
                    f"Completed {test_name} tests: {len(findings)} findings",
                )
            except asyncio.TimeoutError:
                self._logger.warning(
                    self._MODULE,
                    f"Timeout during {test_name} tests for {endpoint}",
                )
                all_findings.append(
                    RawFinding(
                        check=f"{test_name}-timeout",
                        category="availability",
                        location=endpoint,
                        evidence=f"Test '{test_name}' timed out after {timeout}s",
                        context={"reason": "timeout"},
                    )
                )
            except httpx.ConnectError as e:
                self._logger.warning(
                    self._MODULE,
                    f"Connection error during {test_name}: {e}",
                )
                all_findings.append(
                    RawFinding(
                        check=f"{test_name}-unreachable",
                        category="availability",
                        location=endpoint,
                        evidence=f"Endpoint unreachable: {e}",
                        context={"reason": "unreachable"},
                    )
                )

        # Schema conformance requires multiple responses, run separately
        try:
            schema_findings = await asyncio.wait_for(
                self._test_schema_conformance(endpoint),
                timeout=timeout,
            )
            all_findings.extend(schema_findings)
            self._logger.info(
                self._MODULE,
                f"Completed schema conformance tests: {len(schema_findings)} findings",
            )
        except asyncio.TimeoutError:
            self._logger.warning(
                self._MODULE,
                f"Timeout during schema conformance tests for {endpoint}",
            )
            all_findings.append(
                RawFinding(
                    check="schema-conformance-timeout",
                    category="availability",
                    location=endpoint,
                    evidence=f"Schema conformance test timed out after {timeout}s",
                    context={"reason": "timeout"},
                )
            )
        except httpx.ConnectError as e:
            self._logger.warning(
                self._MODULE,
                f"Connection error during schema conformance: {e}",
            )

        # Process findings through AI engine
        self._logger.info(
            self._MODULE,
            f"Processing {len(all_findings)} findings through AI engine",
        )
        context = AnalysisContext(
            mode=AnalysisMode.API,
            target=target,
            additional_context={"endpoint": endpoint},
        )
        issues = await self._ai_engine.process_findings(all_findings, context)

        # Post-process: truncate evidence to 500 chars (Requirement 21.4)
        for issue in issues:
            issue.evidence = truncate_evidence(issue.evidence)

        # Calculate score, grade, and risk level
        score = self._scoring_engine.calculate_score(issues)
        grade = self._scoring_engine.derive_grade(score)
        risk_level_str = self._scoring_engine.derive_risk_level(issues)

        risk_level = RiskLevel(risk_level_str)

        metadata = AnalysisMetadata(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=target,
            mode=AnalysisMode.API,
        )

        issue_count = len(issues)
        summary = (
            f"API analysis of {target} found {issue_count} issue"
            f"{'s' if issue_count != 1 else ''} across authentication, "
            f"response integrity, schema conformance, injection, "
            f"and rate limiting categories."
        )
        if len(summary) > 500:
            summary = summary[:497] + "..."

        result = AnalysisResult(
            score=score,
            grade=grade,
            risk_level=risk_level,
            issues=issues,
            summary=summary,
            metadata=metadata,
        )

        self._logger.info(
            self._MODULE,
            f"API analysis complete. Score: {score}, Grade: {grade}",
        )
        return result

    async def _test_authentication(self, endpoint: str) -> list[RawFinding]:
        """Test authentication enforcement on the endpoint.

        Tests:
        - Request without credentials (expect 401/403)
        - Expired token
        - Malformed token
        - Invalid signature token
        - BOLA (Broken Object Level Authorization)
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing authentication for {endpoint}")

        # Test 1: Request without authentication credentials
        try:
            response = await self._http_client.get(
                endpoint, headers={"Authorization": ""}
            )
            if response.status_code not in (401, 403):
                findings.append(
                    RawFinding(
                        check="missing-auth-enforcement",
                        category="authentication",
                        location=endpoint,
                        evidence=(
                            f"Endpoint returned {response.status_code} without "
                            f"credentials (expected 401 or 403)"
                        ),
                        context={
                            "test_type": "no_credentials",
                            "status_code": response.status_code,
                            "result": "fail",
                        },
                    )
                )
            else:
                self._logger.debug(
                    self._MODULE,
                    f"Auth enforcement OK: {response.status_code} without creds",
                )
        except httpx.RequestError as e:
            self._logger.warning(
                self._MODULE, f"Request error during no-auth test: {e}"
            )
            findings.append(
                RawFinding(
                    check="auth-test-error",
                    category="authentication",
                    location=endpoint,
                    evidence=f"Request failed: {e}",
                    context={"test_type": "no_credentials", "reason": "error"},
                )
            )

        # Test 2: Expired token
        expired_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxMDAwMDAwMDAwfQ."
            "invalid_signature_here"
        )
        try:
            response = await self._http_client.get(
                endpoint,
                headers={"Authorization": f"Bearer {expired_token}"},
            )
            if response.status_code not in (401, 403):
                findings.append(
                    RawFinding(
                        check="expired-token-accepted",
                        category="authentication",
                        location=endpoint,
                        evidence=(
                            f"Endpoint returned {response.status_code} with expired "
                            f"token (expected 401 or 403)"
                        ),
                        context={
                            "test_type": "expired_token",
                            "status_code": response.status_code,
                            "result": "fail",
                        },
                    )
                )
        except httpx.RequestError as e:
            self._logger.warning(
                self._MODULE, f"Request error during expired token test: {e}"
            )

        # Test 3: Malformed token
        malformed_token = "not-a-valid-jwt-token-at-all"
        try:
            response = await self._http_client.get(
                endpoint,
                headers={"Authorization": f"Bearer {malformed_token}"},
            )
            if response.status_code not in (401, 403):
                findings.append(
                    RawFinding(
                        check="malformed-token-accepted",
                        category="authentication",
                        location=endpoint,
                        evidence=(
                            f"Endpoint returned {response.status_code} with malformed "
                            f"token (expected 401 or 403)"
                        ),
                        context={
                            "test_type": "malformed_token",
                            "status_code": response.status_code,
                            "result": "fail",
                        },
                    )
                )
        except httpx.RequestError as e:
            self._logger.warning(
                self._MODULE, f"Request error during malformed token test: {e}"
            )

        # Test 4: Invalid signature token
        invalid_sig_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "tampered_signature_value"
        )
        try:
            response = await self._http_client.get(
                endpoint,
                headers={"Authorization": f"Bearer {invalid_sig_token}"},
            )
            if response.status_code not in (401, 403):
                findings.append(
                    RawFinding(
                        check="invalid-signature-accepted",
                        category="authentication",
                        location=endpoint,
                        evidence=(
                            f"Endpoint returned {response.status_code} with invalid "
                            f"signature token (expected 401 or 403)"
                        ),
                        context={
                            "test_type": "invalid_signature",
                            "status_code": response.status_code,
                            "result": "fail",
                        },
                    )
                )
        except httpx.RequestError as e:
            self._logger.warning(
                self._MODULE, f"Request error during invalid signature test: {e}"
            )

        # Test 5: BOLA (Broken Object Level Authorization)
        # Attempt to access another user's resource by modifying the path
        bola_paths = [
            f"{endpoint}/users/999999",
            f"{endpoint}/accounts/other-user-id",
            f"{endpoint}/profile/admin",
        ]
        for bola_path in bola_paths:
            try:
                response = await self._http_client.get(bola_path)
                if response.status_code in range(200, 300):
                    findings.append(
                        RawFinding(
                            check="bola-vulnerability",
                            category="authentication",
                            location=bola_path,
                            evidence=(
                                f"Endpoint returned {response.status_code} when "
                                f"accessing another user's resource without proper "
                                f"authorization"
                            ),
                            context={
                                "test_type": "bola",
                                "status_code": response.status_code,
                                "result": "fail",
                            },
                        )
                    )
            except httpx.RequestError:
                pass  # Skip unreachable BOLA paths

        return findings

    async def _test_response_integrity(self, endpoint: str) -> list[RawFinding]:
        """Test response integrity for information leakage and mismatches.

        Detects:
        - Stack traces, DB queries, file paths in error responses
        - Status code mismatches (error body with 2xx, data body with 4xx/5xx)
        - Sensitive field exposure (password, secret, token, private_key)
        """
        findings: list[RawFinding] = []
        self._logger.debug(
            self._MODULE, f"Testing response integrity for {endpoint}"
        )

        # Get a normal response first
        try:
            response = await self._http_client.get(endpoint)
        except httpx.RequestError as e:
            self._logger.warning(
                self._MODULE, f"Cannot reach endpoint for integrity test: {e}"
            )
            return findings

        body_text = response.text
        status_code = response.status_code

        # Check for stack traces and internal info in error responses
        if status_code >= 400:
            for pattern in self._STACK_TRACE_PATTERNS:
                if pattern.lower() in body_text.lower():
                    findings.append(
                        RawFinding(
                            check="stack-trace-exposure",
                            category="response_integrity",
                            location=endpoint,
                            evidence=(
                                f"Error response ({status_code}) contains stack "
                                f"trace pattern: '{pattern}'"
                            ),
                            context={
                                "status_code": status_code,
                                "pattern": pattern,
                            },
                        )
                    )
                    break  # One finding per category is sufficient

            for pattern in self._DB_QUERY_PATTERNS:
                if pattern.lower() in body_text.lower():
                    findings.append(
                        RawFinding(
                            check="db-query-exposure",
                            category="response_integrity",
                            location=endpoint,
                            evidence=(
                                f"Error response ({status_code}) contains DB query "
                                f"pattern: '{pattern}'"
                            ),
                            context={
                                "status_code": status_code,
                                "pattern": pattern,
                            },
                        )
                    )
                    break

            for pattern in self._FILE_PATH_PATTERNS:
                if pattern.lower() in body_text.lower():
                    findings.append(
                        RawFinding(
                            check="file-path-exposure",
                            category="response_integrity",
                            location=endpoint,
                            evidence=(
                                f"Error response ({status_code}) contains file "
                                f"path pattern: '{pattern}'"
                            ),
                            context={
                                "status_code": status_code,
                                "pattern": pattern,
                            },
                        )
                    )
                    break

        # Also trigger error responses to check for info leakage
        error_paths = [
            f"{endpoint}/nonexistent-path-404",
            f"{endpoint}/%00",
            f"{endpoint}/../../../etc/passwd",
        ]
        for error_path in error_paths:
            try:
                err_response = await self._http_client.get(error_path)
                if err_response.status_code >= 400:
                    err_body = err_response.text
                    for pattern in self._STACK_TRACE_PATTERNS:
                        if pattern.lower() in err_body.lower():
                            findings.append(
                                RawFinding(
                                    check="stack-trace-exposure",
                                    category="response_integrity",
                                    location=error_path,
                                    evidence=(
                                        f"Error response ({err_response.status_code})"
                                        f" contains stack trace: '{pattern}'"
                                    ),
                                    context={
                                        "status_code": err_response.status_code,
                                        "pattern": pattern,
                                    },
                                )
                            )
                            break
            except httpx.RequestError:
                pass

        # Check for status code mismatches
        try:
            response_json = response.json()
            if isinstance(response_json, dict):
                # Error body with 2xx status
                has_error_indicators = any(
                    key in response_json
                    for key in ("error", "error_message", "error_code", "errors")
                )
                if status_code in range(200, 300) and has_error_indicators:
                    findings.append(
                        RawFinding(
                            check="status-code-mismatch",
                            category="response_integrity",
                            location=endpoint,
                            evidence=(
                                f"Response has {status_code} status but body "
                                f"contains error indicators: "
                                f"{[k for k in response_json if 'error' in k.lower()]}"
                            ),
                            context={
                                "status_code": status_code,
                                "mismatch_type": "error_body_with_2xx",
                            },
                        )
                    )

                # Data body with 4xx/5xx status
                has_data_indicators = any(
                    key in response_json
                    for key in ("data", "results", "items", "records")
                )
                has_no_error = not has_error_indicators
                if status_code >= 400 and has_data_indicators and has_no_error:
                    findings.append(
                        RawFinding(
                            check="status-code-mismatch",
                            category="response_integrity",
                            location=endpoint,
                            evidence=(
                                f"Response has {status_code} status but body "
                                f"contains data fields without error indicators"
                            ),
                            context={
                                "status_code": status_code,
                                "mismatch_type": "data_body_with_error_status",
                            },
                        )
                    )
        except (ValueError, TypeError):
            pass  # Non-JSON response, skip mismatch check

        # Check for sensitive field exposure
        try:
            response_json = response.json()
            self._check_sensitive_fields(response_json, endpoint, findings)
        except (ValueError, TypeError):
            pass  # Non-JSON response

        return findings

    def _check_sensitive_fields(
        self,
        data: Any,
        endpoint: str,
        findings: list[RawFinding],
        path: str = "",
    ) -> None:
        """Recursively check for sensitive field names in response data."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()
                for pattern in self._SENSITIVE_PATTERNS:
                    if pattern in key_lower:
                        findings.append(
                            RawFinding(
                                check="sensitive-field-exposure",
                                category="response_integrity",
                                location=endpoint,
                                evidence=(
                                    f"Response contains sensitive field "
                                    f"'{current_path}' matching pattern '{pattern}'"
                                ),
                                context={
                                    "field": current_path,
                                    "pattern": pattern,
                                },
                            )
                        )
                        break
                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    self._check_sensitive_fields(value, endpoint, findings, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):  # Check first 5 items
                self._check_sensitive_fields(
                    item, endpoint, findings, f"{path}[{i}]"
                )

    async def _test_schema_conformance(self, endpoint: str) -> list[RawFinding]:
        """Test schema conformance by comparing multiple responses.

        Validates field types against a reference schema inferred from 2+
        responses. Detects unexpected nulls in fields that were previously
        non-null.
        """
        findings: list[RawFinding] = []
        self._logger.debug(
            self._MODULE, f"Testing schema conformance for {endpoint}"
        )

        # Collect multiple responses to build reference schema
        responses: list[dict[str, Any]] = []
        for _ in range(3):
            try:
                response = await self._http_client.get(endpoint)
                if response.status_code in range(200, 300):
                    data = response.json()
                    if isinstance(data, dict):
                        responses.append(data)
            except (httpx.RequestError, ValueError, TypeError):
                pass

        if len(responses) < 2:
            self._logger.debug(
                self._MODULE,
                "Insufficient responses for schema inference (need 2+)",
            )
            return findings

        # Build reference schema from first response
        reference_schema = self._infer_schema(responses[0])

        # Validate subsequent responses against reference
        for i, resp_data in enumerate(responses[1:], start=2):
            type_mismatches = self._check_type_conformance(
                resp_data, reference_schema, ""
            )
            for field_path, expected_type, actual_type in type_mismatches:
                findings.append(
                    RawFinding(
                        check="schema-type-mismatch",
                        category="schema_conformance",
                        location=endpoint,
                        evidence=(
                            f"Field '{field_path}' expected type '{expected_type}' "
                            f"but got '{actual_type}' in response #{i}"
                        ),
                        context={
                            "field": field_path,
                            "expected_type": expected_type,
                            "actual_type": actual_type,
                            "response_index": i,
                        },
                    )
                )

        # Check for unexpected nulls
        # Fields that were non-null in all prior responses
        non_null_fields = self._get_non_null_fields(responses[0])
        for i, resp_data in enumerate(responses[1:], start=2):
            null_fields = self._find_unexpected_nulls(resp_data, non_null_fields, "")
            for field_path in null_fields:
                findings.append(
                    RawFinding(
                        check="unexpected-null",
                        category="schema_conformance",
                        location=endpoint,
                        evidence=(
                            f"Field '{field_path}' is null in response #{i} but "
                            f"was non-null in prior responses"
                        ),
                        context={
                            "field": field_path,
                            "response_index": i,
                        },
                    )
                )

        return findings

    def _infer_schema(self, data: dict[str, Any]) -> dict[str, str]:
        """Infer a flat type schema from a response dict."""
        schema: dict[str, str] = {}
        self._extract_types(data, "", schema)
        return schema

    def _extract_types(
        self, data: Any, prefix: str, schema: dict[str, str]
    ) -> None:
        """Recursively extract field types into a flat schema."""
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if value is None:
                    schema[path] = "null"
                elif isinstance(value, dict):
                    schema[path] = "object"
                    self._extract_types(value, path, schema)
                elif isinstance(value, list):
                    schema[path] = "array"
                elif isinstance(value, bool):
                    schema[path] = "boolean"
                elif isinstance(value, int):
                    schema[path] = "integer"
                elif isinstance(value, float):
                    schema[path] = "number"
                elif isinstance(value, str):
                    schema[path] = "string"
                else:
                    schema[path] = type(value).__name__

    def _check_type_conformance(
        self,
        data: Any,
        schema: dict[str, str],
        prefix: str,
    ) -> list[tuple[str, str, str]]:
        """Check data against reference schema, return mismatches."""
        mismatches: list[tuple[str, str, str]] = []
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if path in schema:
                    expected = schema[path]
                    actual = self._get_type_name(value)
                    # Allow null for any field (handled by null check)
                    if actual != "null" and actual != expected:
                        mismatches.append((path, expected, actual))
                    # Recurse into nested objects
                    if isinstance(value, dict):
                        mismatches.extend(
                            self._check_type_conformance(value, schema, path)
                        )
        return mismatches

    def _get_type_name(self, value: Any) -> str:
        """Get the type name for a value."""
        if value is None:
            return "null"
        elif isinstance(value, dict):
            return "object"
        elif isinstance(value, list):
            return "array"
        elif isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "number"
        elif isinstance(value, str):
            return "string"
        return type(value).__name__

    def _get_non_null_fields(self, data: dict[str, Any]) -> set[str]:
        """Get set of field paths that are non-null in the data."""
        non_null: set[str] = set()
        self._collect_non_null(data, "", non_null)
        return non_null

    def _collect_non_null(
        self, data: Any, prefix: str, non_null: set[str]
    ) -> None:
        """Recursively collect non-null field paths."""
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if value is not None:
                    non_null.add(path)
                    if isinstance(value, dict):
                        self._collect_non_null(value, path, non_null)

    def _find_unexpected_nulls(
        self,
        data: Any,
        non_null_fields: set[str],
        prefix: str,
    ) -> list[str]:
        """Find fields that are null but were non-null in reference."""
        unexpected: list[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if value is None and path in non_null_fields:
                    unexpected.append(path)
                elif isinstance(value, dict):
                    unexpected.extend(
                        self._find_unexpected_nulls(value, non_null_fields, path)
                    )
        return unexpected

    async def _test_injection(self, endpoint: str) -> list[RawFinding]:
        """Test for injection vulnerabilities.

        Sends 5+ payloads per category (SQL, NoSQL, command injection).
        Detects error messages and time deviations >5s.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing injection for {endpoint}")

        # Get baseline response time
        baseline_time = await self._get_baseline_time(endpoint)
        if baseline_time is None:
            self._logger.warning(
                self._MODULE, "Cannot establish baseline for injection tests"
            )
            return findings

        # Test SQL injection
        sql_findings = await self._test_injection_category(
            endpoint, "sql", self._SQL_PAYLOADS, baseline_time
        )
        findings.extend(sql_findings)

        # Test NoSQL injection
        nosql_findings = await self._test_injection_category(
            endpoint, "nosql", self._NOSQL_PAYLOADS, baseline_time
        )
        findings.extend(nosql_findings)

        # Test command injection
        cmd_findings = await self._test_injection_category(
            endpoint, "command", self._CMD_PAYLOADS, baseline_time
        )
        findings.extend(cmd_findings)

        return findings

    async def _get_baseline_time(self, endpoint: str) -> float | None:
        """Get baseline response time for the endpoint."""
        try:
            start = time.monotonic()
            await self._http_client.get(endpoint)
            return time.monotonic() - start
        except httpx.RequestError:
            return None

    async def _test_injection_category(
        self,
        endpoint: str,
        category: str,
        payloads: list[str],
        baseline_time: float,
    ) -> list[RawFinding]:
        """Test a category of injection payloads against the endpoint."""
        findings: list[RawFinding] = []

        for payload in payloads:
            try:
                # Send payload as query parameter
                start = time.monotonic()
                response = await self._http_client.get(
                    endpoint, params={"input": payload, "q": payload}
                )
                elapsed = time.monotonic() - start

                body_text = response.text.lower()

                # Check for error messages indicating injection success
                injection_indicators = [
                    "syntax error",
                    "sql error",
                    "mysql",
                    "postgresql",
                    "sqlite",
                    "oracle",
                    "mongodb",
                    "command not found",
                    "permission denied",
                    "/bin/",
                    "root:",
                    "no such file",
                    "unclosed quotation",
                    "unterminated",
                ]

                for indicator in injection_indicators:
                    if indicator in body_text:
                        findings.append(
                            RawFinding(
                                check=f"{category}-injection-detected",
                                category="injection",
                                location=endpoint,
                                evidence=(
                                    f"Payload '{payload}' triggered error "
                                    f"indicator '{indicator}' in response"
                                ),
                                context={
                                    "payload": payload,
                                    "category": category,
                                    "indicator": indicator,
                                    "status_code": response.status_code,
                                },
                            )
                        )
                        break

                # Check for time-based injection (>5s deviation)
                time_deviation = elapsed - baseline_time
                if time_deviation > 5.0:
                    findings.append(
                        RawFinding(
                            check=f"{category}-time-based-injection",
                            category="injection",
                            location=endpoint,
                            evidence=(
                                f"Payload '{payload}' caused {time_deviation:.2f}s "
                                f"time deviation (baseline: {baseline_time:.2f}s, "
                                f"actual: {elapsed:.2f}s)"
                            ),
                            context={
                                "payload": payload,
                                "category": category,
                                "baseline_time": baseline_time,
                                "actual_time": elapsed,
                                "deviation": time_deviation,
                            },
                        )
                    )

            except httpx.RequestError:
                pass  # Skip payloads that cause connection errors

        return findings

    async def _test_rate_limiting(
        self, endpoint: str, config: AnalysisConfig | None = None
    ) -> list[RawFinding]:
        """Test rate limiting by sending a burst of requests.

        Sends configurable burst (default 50 in 10s), checks for 429
        and Retry-After header.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing rate limiting for {endpoint}")

        burst_count = 50
        burst_window = 10
        if config:
            burst_count = config.rate_limit_burst or 50
            burst_window = config.rate_limit_window or 10

        # Send burst of requests
        got_429 = False
        has_retry_after = False
        responses: list[int] = []

        # Calculate delay between requests to fit within window
        delay = burst_window / burst_count if burst_count > 0 else 0

        for i in range(burst_count):
            try:
                response = await self._http_client.get(endpoint)
                responses.append(response.status_code)

                if response.status_code == 429:
                    got_429 = True
                    if "retry-after" in response.headers:
                        has_retry_after = True
                    break  # Rate limit triggered, stop sending

                # Small delay to stay within the burst window
                if delay > 0 and i < burst_count - 1:
                    await asyncio.sleep(delay)

            except httpx.RequestError:
                break  # Stop on connection errors

        # Evaluate results
        if not got_429:
            findings.append(
                RawFinding(
                    check="missing-rate-limiting",
                    category="rate_limiting",
                    location=endpoint,
                    evidence=(
                        f"Sent {len(responses)} requests in {burst_window}s burst "
                        f"without receiving 429 status code. "
                        f"Rate limiting may not be implemented."
                    ),
                    context={
                        "burst_count": burst_count,
                        "burst_window": burst_window,
                        "requests_sent": len(responses),
                        "status_codes": responses[-10:],  # Last 10 codes
                    },
                )
            )
        elif not has_retry_after:
            findings.append(
                RawFinding(
                    check="missing-retry-after-header",
                    category="rate_limiting",
                    location=endpoint,
                    evidence=(
                        f"Rate limiting (429) triggered after {len(responses)} "
                        f"requests but Retry-After header is missing"
                    ),
                    context={
                        "burst_count": burst_count,
                        "requests_sent": len(responses),
                        "got_429": True,
                        "has_retry_after": False,
                    },
                )
            )

        return findings


    # --- Task 1: Audit Log Manipulation ---

    async def _test_audit_log_manipulation(self, endpoint: str) -> list[RawFinding]:
        """Test for audit log manipulation via API (log injection through headers/params).

        Sends requests with newline characters in headers/params to detect
        log injection vulnerabilities.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing audit log manipulation for {endpoint}")

        # Log injection payloads with newline characters
        injection_payloads = [
            "test%0aINJECTED_LOG_ENTRY",
            "test%0dINJECTED_LOG_ENTRY",
            "test\nFake log entry: admin logged in",
            "test\r\nFake log entry: admin logged in",
        ]

        for payload in injection_payloads:
            try:
                # Send payload in query parameter
                response = await self._http_client.get(
                    endpoint, params={"user": payload, "action": payload}
                )
                body_text = response.text.lower()

                # Check if injected content appears reflected in response
                if "injected_log_entry" in body_text or "fake log entry" in body_text:
                    findings.append(
                        RawFinding(
                            check="api-log-injection",
                            category="security",
                            location=endpoint,
                            evidence=(
                                f"Log injection payload reflected in response. "
                                f"Payload: '{payload[:50]}', Status: {response.status_code}"
                            ),
                            context={
                                "payload": payload,
                                "status_code": response.status_code,
                                "vulnerability_type": "audit-log-manipulation",
                            },
                        )
                    )
                    break

            except httpx.RequestError:
                pass

        # Test with newline in custom headers
        try:
            response = await self._http_client.get(
                endpoint,
                headers={"X-Custom-User": "admin\r\nX-Injected: true"},
            )
            if response.status_code not in (400, 431):
                # Server accepted header with newline - potential CRLF injection
                findings.append(
                    RawFinding(
                        check="api-log-injection",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Server accepted header with CRLF characters "
                            f"(status: {response.status_code}). Potential log injection."
                        ),
                        context={
                            "test_type": "crlf_header",
                            "status_code": response.status_code,
                            "vulnerability_type": "audit-log-manipulation",
                        },
                    )
                )
        except httpx.RequestError:
            pass

        return findings

    # --- Task 2: CAPTCHA Bypass ---

    async def _test_captcha_bypass(self, endpoint: str) -> list[RawFinding]:
        """Test if auth/registration endpoints can be accessed without CAPTCHA.

        POSTs to common auth endpoints without any CAPTCHA token to check
        if they are bypassable.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing CAPTCHA bypass for {endpoint}")

        # Common auth/registration endpoint paths
        auth_paths = [
            f"{endpoint}/login",
            f"{endpoint}/register",
            f"{endpoint}/signup",
            f"{endpoint}/auth/login",
            f"{endpoint}/auth/register",
            f"{endpoint}/api/login",
            f"{endpoint}/api/register",
        ]

        for auth_path in auth_paths:
            try:
                # POST without CAPTCHA token
                response = await self._http_client.post(
                    auth_path,
                    json={"username": "test", "password": "test123"},
                )
                # If response is success without CAPTCHA, flag it
                if response.status_code in (200, 201):
                    findings.append(
                        RawFinding(
                            check="captcha-bypass",
                            category="security",
                            location=auth_path,
                            evidence=(
                                f"Auth endpoint returned {response.status_code} "
                                f"without CAPTCHA token. Endpoint may be bypassable."
                            ),
                            context={
                                "status_code": response.status_code,
                                "vulnerability_type": "captcha-bypass",
                            },
                        )
                    )
            except httpx.RequestError:
                pass  # Endpoint doesn't exist, skip

        return findings

    # --- Task 3: HTTP Request Smuggling ---

    async def _test_http_request_smuggling(self, endpoint: str) -> list[RawFinding]:
        """Test for HTTP request smuggling (CL.TE / TE.CL).

        Sends requests with conflicting Content-Length and Transfer-Encoding
        headers to detect desync vulnerabilities.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing HTTP request smuggling for {endpoint}")

        # CL.TE probe: Content-Length says short, Transfer-Encoding says chunked
        try:
            response = await self._http_client.post(
                endpoint,
                headers={
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=b"0\r\n\r\nSMUGGLED",
            )
            # Unexpected responses may indicate vulnerability
            if response.status_code in (400, 505):
                body = response.text.lower()
                if "invalid" in body or "bad request" in body:
                    findings.append(
                        RawFinding(
                            check="http-request-smuggling-cl-te",
                            category="security",
                            location=endpoint,
                            evidence=(
                                f"CL.TE probe triggered error response ({response.status_code}). "
                                f"Server may be vulnerable to request smuggling."
                            ),
                            context={
                                "probe_type": "CL.TE",
                                "status_code": response.status_code,
                                "vulnerability_type": "http-request-smuggling",
                            },
                        )
                    )
        except httpx.RequestError:
            pass

        # TE.CL probe: obfuscated Transfer-Encoding
        try:
            response = await self._http_client.post(
                endpoint,
                headers={
                    "Content-Length": "50",
                    "Transfer-Encoding": "xchunked",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=b"0\r\n\r\n",
            )
            if response.status_code in (400, 505):
                body = response.text.lower()
                if "invalid" in body or "bad request" in body:
                    findings.append(
                        RawFinding(
                            check="http-request-smuggling-te-cl",
                            category="security",
                            location=endpoint,
                            evidence=(
                                f"TE.CL probe triggered error response ({response.status_code}). "
                                f"Server may be vulnerable to request smuggling."
                            ),
                            context={
                                "probe_type": "TE.CL",
                                "status_code": response.status_code,
                                "vulnerability_type": "http-request-smuggling",
                            },
                        )
                    )
        except httpx.RequestError:
            pass

        return findings

    # --- Task 4: Case Sensitivity ---

    async def _test_case_sensitivity(self, endpoint: str) -> list[RawFinding]:
        """Test for case-sensitive route/auth bypass.

        Sends the same request with URL path variations (original, uppercase,
        mixed case) and compares HTTP status codes.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing case sensitivity for {endpoint}")

        from urllib.parse import urlparse

        parsed = urlparse(endpoint)
        path = parsed.path

        if not path or path == "/":
            return findings

        # Generate case variations
        variations = [
            ("original", endpoint),
            ("uppercase", endpoint.replace(path, path.upper())),
            ("mixed", endpoint.replace(path, path.title())),
        ]

        status_codes: dict[str, int] = {}
        for variant_name, variant_url in variations:
            try:
                response = await self._http_client.get(variant_url)
                status_codes[variant_name] = response.status_code
            except httpx.RequestError:
                status_codes[variant_name] = -1

        # Check if status codes differ (potential bypass)
        original_status = status_codes.get("original", -1)
        for variant_name in ("uppercase", "mixed"):
            variant_status = status_codes.get(variant_name, -1)
            if variant_status == -1 or original_status == -1:
                continue
            # If original is forbidden but variant is accessible
            if original_status in (401, 403) and variant_status in range(200, 300):
                findings.append(
                    RawFinding(
                        check="case-sensitive-route-bypass",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Case sensitivity bypass detected: original path "
                            f"returns {original_status}, {variant_name} variant "
                            f"returns {variant_status}"
                        ),
                        context={
                            "original_status": original_status,
                            "variant_status": variant_status,
                            "variant_type": variant_name,
                            "vulnerability_type": "case-sensitivity",
                        },
                    )
                )
            # If status codes differ significantly
            elif abs(original_status - variant_status) >= 100 and variant_status > 0:
                findings.append(
                    RawFinding(
                        check="case-sensitive-auth-bypass",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Inconsistent case handling: original={original_status}, "
                            f"{variant_name}={variant_status}"
                        ),
                        context={
                            "original_status": original_status,
                            "variant_status": variant_status,
                            "variant_type": variant_name,
                            "vulnerability_type": "case-sensitivity",
                        },
                    )
                )

        # Test Authorization header casing
        auth_headers = [
            ("Authorization", "Bearer test-token"),
            ("authorization", "Bearer test-token"),
            ("AUTHORIZATION", "Bearer test-token"),
        ]
        auth_statuses: list[int] = []
        for header_name, header_value in auth_headers:
            try:
                response = await self._http_client.get(
                    endpoint, headers={header_name: header_value}
                )
                auth_statuses.append(response.status_code)
            except httpx.RequestError:
                auth_statuses.append(-1)

        # If different header casings produce different results
        valid_statuses = [s for s in auth_statuses if s > 0]
        if len(set(valid_statuses)) > 1:
            findings.append(
                RawFinding(
                    check="case-sensitive-auth-bypass",
                    category="security",
                    location=endpoint,
                    evidence=(
                        f"Authorization header case sensitivity detected. "
                        f"Different casings produce different status codes: {valid_statuses}"
                    ),
                    context={
                        "status_codes": valid_statuses,
                        "vulnerability_type": "case-sensitivity",
                    },
                )
            )

        return findings

    # --- Task 5: JSON Hijacking ---

    async def _test_json_hijacking(self, endpoint: str) -> list[RawFinding]:
        """Test for JSON hijacking vulnerabilities.

        Checks if the endpoint returns top-level JSON arrays without proper
        protections (CSRF headers, JSON prefix mitigations).
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing JSON hijacking for {endpoint}")

        try:
            response = await self._http_client.get(endpoint)
        except httpx.RequestError:
            return findings

        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return findings

        body = response.text.strip()

        # Check if response is a top-level JSON array
        if body.startswith("["):
            # Check for JSON hijacking mitigations
            has_prefix = (
                body.startswith(")]}',\n")
                or body.startswith("while(1);")
                or body.startswith("for(;;);")
            )

            if not has_prefix:
                findings.append(
                    RawFinding(
                        check="json-hijacking-top-level-array",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Endpoint returns top-level JSON array without "
                            f"anti-hijacking prefix. Content-Type: {content_type}"
                        ),
                        context={
                            "vulnerability_type": "json-hijacking",
                            "content_type": content_type,
                        },
                    )
                )

            # Check for missing CSRF protection headers
            x_frame = response.headers.get("x-frame-options")
            csp = response.headers.get("content-security-policy")
            cors = response.headers.get("access-control-allow-origin")

            if not x_frame and not csp:
                findings.append(
                    RawFinding(
                        check="json-hijacking-no-prefix",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"JSON array endpoint missing X-Frame-Options and CSP headers. "
                            f"Vulnerable to cross-origin data theft."
                        ),
                        context={
                            "vulnerability_type": "json-hijacking",
                            "missing_headers": ["X-Frame-Options", "Content-Security-Policy"],
                        },
                    )
                )

            # Check if accessible cross-origin
            if cors == "*":
                findings.append(
                    RawFinding(
                        check="json-hijacking-no-prefix",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"JSON array endpoint has Access-Control-Allow-Origin: *. "
                            f"Data accessible from any origin."
                        ),
                        context={
                            "vulnerability_type": "json-hijacking",
                            "cors": cors,
                        },
                    )
                )

        return findings

    # --- Open Redirect ---

    async def _test_open_redirect(self, endpoint: str) -> list[RawFinding]:
        """Test for open redirect vulnerabilities via common redirect parameters.

        Sends requests with external URLs in redirect-related query parameters
        and checks if the server follows or reflects them.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing open redirect for {endpoint}")

        redirect_params = [
            "redirect", "redirect_uri", "redirect_url", "return", "return_url",
            "returnto", "next", "url", "goto", "target", "destination", "redir",
            "continue", "forward",
        ]
        external_url = "https://evil.example.com/phishing"

        for param in redirect_params:
            try:
                response = await self._http_client.get(
                    endpoint,
                    params={param: external_url},
                    follow_redirects=False,
                )
                # Flag if server issues a redirect to the external URL
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location", "")
                    if "evil.example.com" in location or external_url in location:
                        findings.append(
                            RawFinding(
                                check="open-redirect",
                                category="security",
                                location=f"{endpoint}?{param}={external_url}",
                                evidence=(
                                    f"Endpoint redirects to attacker-controlled URL via "
                                    f"parameter '{param}'. Location: {location[:200]}"
                                ),
                                context={
                                    "param": param,
                                    "location": location[:200],
                                    "status_code": response.status_code,
                                    "vulnerability_type": "open-redirect",
                                    "severity_hint": "medium",
                                },
                            )
                        )
                        break  # One finding is enough
            except httpx.RequestError:
                pass

        return findings

    # --- Server Version / Technology Disclosure ---

    async def _test_server_version_disclosure(self, endpoint: str) -> list[RawFinding]:
        """Test for server version and technology information in response headers.

        Checks Server, X-Powered-By, X-AspNet-Version and similar headers
        that leak version information useful to attackers.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing server version disclosure for {endpoint}")

        import re as _re

        try:
            response = await self._http_client.get(endpoint)
        except httpx.RequestError as e:
            self._logger.warning(self._MODULE, f"Cannot reach endpoint for version disclosure test: {e}")
            return findings

        disclosure_headers = {
            "Server": "server-version-disclosure",
            "X-Powered-By": "technology-disclosure",
            "X-AspNet-Version": "aspnet-version-disclosure",
            "X-AspNetMvc-Version": "aspnet-mvc-version-disclosure",
            "X-Generator": "generator-disclosure",
        }

        version_pattern = _re.compile(r'\d+\.\d+')
        tech_keywords = [
            "apache", "nginx", "iis", "php", "asp", "express", "django",
            "rails", "tomcat", "jetty", "gunicorn", "uvicorn", "werkzeug",
            "python", "ruby", "java", "node", "microsoft",
        ]

        for header_name, check_name in disclosure_headers.items():
            value = response.headers.get(header_name)
            if not value:
                continue

            has_version = bool(version_pattern.search(value))
            has_tech = any(kw in value.lower() for kw in tech_keywords)

            if has_version or has_tech:
                findings.append(
                    RawFinding(
                        check=check_name,
                        category="response_integrity",
                        location=endpoint,
                        evidence=(
                            f"Header '{header_name}' discloses version/technology: '{value}'. "
                            f"Attackers can use this to target known vulnerabilities."
                        ),
                        context={
                            "severity_hint": "low",
                            "header": header_name,
                            "value": value,
                            "vulnerability_type": "information-disclosure",
                        },
                    )
                )

        return findings

    # --- Internal IP / Domain Leakage ---

    async def _test_internal_ip_leakage(self, endpoint: str) -> list[RawFinding]:
        """Test for internal IP addresses and private domain names in API responses.

        Scans response bodies for RFC 1918 private IP ranges and internal
        hostnames that should not be exposed to external clients.
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing internal IP leakage for {endpoint}")

        import re as _re

        # RFC 1918 private IP ranges + loopback + link-local
        private_ip_pattern = _re.compile(
            r'\b(?:'
            r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'          # 10.0.0.0/8
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'  # 172.16.0.0/12
            r'|192\.168\.\d{1,3}\.\d{1,3}'             # 192.168.0.0/16
            r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'         # 127.0.0.0/8 loopback
            r'|169\.254\.\d{1,3}\.\d{1,3}'             # 169.254.0.0/16 link-local
            r'|::1'                                      # IPv6 loopback
            r'|fc[0-9a-f]{2}:'                          # IPv6 ULA
            r')\b'
        )

        # Internal hostname patterns
        internal_hostname_pattern = _re.compile(
            r'\b(?:localhost|internal|intranet|corp|local|private|dev|staging|test)\b'
            r'(?:\.\w+)*',
            _re.IGNORECASE,
        )

        # Probe multiple paths
        probe_paths = [
            endpoint,
            f"{endpoint}/health",
            f"{endpoint}/status",
            f"{endpoint}/debug",
            f"{endpoint}/info",
        ]

        for path in probe_paths:
            try:
                response = await self._http_client.get(path)
                body = response.text

                # Check for private IPs
                ip_matches = private_ip_pattern.findall(body)
                if ip_matches:
                    unique_ips = list(dict.fromkeys(ip_matches))[:5]
                    findings.append(
                        RawFinding(
                            check="internal-ip-leakage",
                            category="response_integrity",
                            location=path,
                            evidence=(
                                f"Response body contains private/internal IP address(es): "
                                f"{', '.join(unique_ips)}. These should not be exposed externally."
                            ),
                            context={
                                "ips": unique_ips,
                                "status_code": response.status_code,
                                "vulnerability_type": "information-disclosure",
                                "severity_hint": "low",
                            },
                        )
                    )

                # Check for internal hostnames
                hostname_matches = internal_hostname_pattern.findall(body)
                if hostname_matches:
                    unique_hosts = list(dict.fromkeys(hostname_matches))[:5]
                    findings.append(
                        RawFinding(
                            check="internal-domain-leakage",
                            category="response_integrity",
                            location=path,
                            evidence=(
                                f"Response body contains internal hostname(s): "
                                f"{', '.join(unique_hosts)}. Internal infrastructure details exposed."
                            ),
                            context={
                                "hostnames": unique_hosts,
                                "status_code": response.status_code,
                                "vulnerability_type": "information-disclosure",
                                "severity_hint": "low",
                            },
                        )
                    )

            except httpx.RequestError:
                pass

        return findings

    # --- Application-Level DoS Vectors ---

    async def _test_application_dos(self, endpoint: str) -> list[RawFinding]:
        """Test for application-level DoS vulnerabilities.

        Checks for missing protections against:
        - Oversized request payloads (no 413 response)
        - Deeply nested JSON (no rejection of recursive structures)
        - Missing request body size limits
        """
        findings: list[RawFinding] = []
        self._logger.debug(self._MODULE, f"Testing application DoS vectors for {endpoint}")

        # Test 1: Large payload — send 1MB body, expect 413 or rejection
        large_payload = "A" * (1024 * 1024)  # 1MB
        try:
            response = await self._http_client.post(
                endpoint,
                content=large_payload.encode(),
                headers={"Content-Type": "text/plain"},
            )
            if response.status_code not in (400, 413, 414, 431):
                findings.append(
                    RawFinding(
                        check="missing-payload-size-limit",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Endpoint accepted a 1MB payload without rejecting it "
                            f"(status: {response.status_code}). No payload size limit detected."
                        ),
                        context={
                            "payload_size_bytes": len(large_payload),
                            "status_code": response.status_code,
                            "vulnerability_type": "application-dos",
                            "severity_hint": "medium",
                        },
                    )
                )
        except httpx.RequestError:
            pass

        # Test 2: Deeply nested JSON — 50 levels deep
        nested: dict = {"x": None}
        current = nested
        for _ in range(50):
            current["x"] = {"x": None}
            current = current["x"]

        try:
            response = await self._http_client.post(
                endpoint,
                json=nested,
            )
            if response.status_code not in (400, 413, 422):
                findings.append(
                    RawFinding(
                        check="missing-json-depth-limit",
                        category="security",
                        location=endpoint,
                        evidence=(
                            f"Endpoint accepted a 50-level deeply nested JSON object "
                            f"(status: {response.status_code}). No JSON depth limit detected. "
                            f"Deep nesting can cause stack overflows or excessive CPU usage."
                        ),
                        context={
                            "nesting_depth": 50,
                            "status_code": response.status_code,
                            "vulnerability_type": "application-dos",
                            "severity_hint": "medium",
                        },
                    )
                )
        except httpx.RequestError:
            pass

        return findings
