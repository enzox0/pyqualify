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
        test_methods = [
            ("authentication", self._test_authentication),
            ("response_integrity", self._test_response_integrity),
            ("injection", self._test_injection),
            ("rate_limiting", self._test_rate_limiting),
        ]

        for test_name, test_method in test_methods:
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

