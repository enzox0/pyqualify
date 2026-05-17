"""Code analyzer for security, quality, bugs, tests, and dependencies."""

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from pyqualify.ai.protocol import AIEngineProtocol
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    BugRiskType,
    RawFinding,
    RiskLevel,
)
from pyqualify.scoring.engine import ScoringEngine
from pyqualify.utils import resolve_location, truncate_evidence

# File extensions to analyze
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".go",
    ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt",
}

# Popular packages for typosquatting detection
POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "tensorflow", "pytorch", "scipy", "matplotlib", "sqlalchemy",
    "celery", "redis", "boto3", "pillow", "cryptography",
    "beautifulsoup4", "selenium", "scrapy", "httpx", "pydantic",
    "express", "react", "lodash", "axios", "moment", "webpack",
    "typescript", "jquery", "angular", "vue", "next", "nest",
]

# Known deprecated packages
DEPRECATED_PACKAGES = [
    "optparse", "imp", "distutils", "asyncore", "asynchat",
    "formatter", "parser", "symbol", "token", "cgi",
]


class CodeAnalyzer:
    """Analyzes source code for security, quality, bugs, tests, and dependencies."""

    def __init__(self, ai_engine: AIEngineProtocol, logger: PyqualifyLogger) -> None:
        self._ai_engine = ai_engine
        self._logger = logger
        self._scoring = ScoringEngine()

    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:
        """Run analysis on the given target path and return structured results.

        Handles both single files and directories (recursively analyzes
        supported code file extensions). Files that cannot be parsed are
        skipped with a diagnostic log message.
        """
        self._logger.info("code_analyzer", f"Starting code analysis on: {target}")
        target_path = Path(target)
        all_findings: list[RawFinding] = []

        # Collect all code files to analyze
        code_files = self._collect_code_files(target_path)
        test_files = [f for f in code_files if self._is_test_file(f)]

        self._logger.info(
            "code_analyzer",
            f"Found {len(code_files)} code files, {len(test_files)} test files",
        )

        for filepath in code_files:
            try:
                source = filepath.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError) as e:
                self._logger.warning(
                    "code_analyzer",
                    f"Cannot read file {filepath}: {e}",
                )
                continue

            file_str = str(filepath)
            try:
                findings = self._analyze_single_file(
                    source, file_str, test_files
                )
                all_findings.extend(findings)
            except Exception as e:
                self._logger.warning(
                    "code_analyzer",
                    f"Parse error in {filepath}: {e}. Skipping file.",
                )
                continue

        # Process findings through AI engine
        context = AnalysisContext(
            mode=AnalysisMode.CODE,
            target=target,
            additional_context={"file_count": len(code_files)},
        )

        self._logger.info(
            "code_analyzer",
            f"Processing {len(all_findings)} raw findings through AI engine",
        )
        issues = await self._ai_engine.process_findings(all_findings, context)

        # Post-process: truncate evidence to 500 chars (Requirement 21.4)
        for issue in issues:
            issue.evidence = truncate_evidence(issue.evidence)

        # Calculate scoring
        score = self._scoring.calculate_score(issues)
        grade = self._scoring.derive_grade(score)
        risk_level_str = self._scoring.derive_risk_level(issues)

        risk_level = RiskLevel(risk_level_str)

        summary = (
            f"Code analysis of {target} found {len(issues)} issues "
            f"across {len(code_files)} files. "
            f"Score: {score}/100, Grade: {grade}."
        )
        if len(summary) > 500:
            summary = summary[:497] + "..."

        metadata = AnalysisMetadata(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target=target,
            mode=AnalysisMode.CODE,
        )

        result = AnalysisResult(
            score=score,
            grade=grade,
            risk_level=risk_level,
            issues=issues,
            summary=summary,
            metadata=metadata,
        )

        self._logger.info(
            "code_analyzer",
            f"Analysis complete. Score: {score}, Grade: {grade}, "
            f"Risk: {risk_level.value}, Issues: {len(issues)}",
        )
        return result

    def _collect_code_files(self, target_path: Path) -> list[Path]:
        """Collect all code files from target path (file or directory)."""
        if target_path.is_file():
            if target_path.suffix in CODE_EXTENSIONS:
                return [target_path]
            return []

        code_files: list[Path] = []
        if target_path.is_dir():
            for root, _dirs, files in os.walk(target_path):
                root_path = Path(root)
                # Skip hidden directories and common non-source dirs
                if any(
                    part.startswith(".")
                    or part in ("node_modules", "__pycache__", "venv", ".venv", "dist", "build")
                    for part in root_path.parts
                ):
                    continue
                for filename in files:
                    file_path = root_path / filename
                    if file_path.suffix in CODE_EXTENSIONS:
                        code_files.append(file_path)
        return code_files

    def _is_test_file(self, filepath: Path) -> bool:
        """Determine if a file is a test file by naming convention."""
        name = filepath.stem.lower()
        parts = [p.lower() for p in filepath.parts]
        return (
            name.startswith("test_")
            or name.endswith("_test")
            or name.startswith("test")
            or "tests" in parts
            or "test" in parts
            or "__tests__" in parts
            or name.endswith(".spec")
            or name.endswith(".test")
        )

    def _analyze_single_file(
        self, source: str, filepath: str, test_files: list[Path]
    ) -> list[RawFinding]:
        """Run all checks on a single source file."""
        findings: list[RawFinding] = []
        findings.extend(self._check_security(source, filepath))
        findings.extend(self._check_bug_risks(source, filepath))
        findings.extend(self._check_quality(source, filepath))
        findings.extend(
            self._check_test_gaps(source, filepath, test_files)
        )
        findings.extend(self._check_dependencies(source, filepath))
        return findings

    # --- Security Checks ---


    def _check_security(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect injection vulnerabilities, hardcoded secrets, insecure patterns."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"

            # SQL Injection patterns
            findings.extend(
                self._check_sql_injection(line, location)
            )
            # Command injection
            findings.extend(
                self._check_command_injection(line, location)
            )
            # XSS patterns
            findings.extend(self._check_xss(line, location))
            # Hardcoded secrets
            findings.extend(
                self._check_hardcoded_secrets(line, location)
            )
            # Insecure deserialization
            findings.extend(
                self._check_insecure_deserialization(line, location)
            )
            # Path traversal
            findings.extend(
                self._check_path_traversal(line, location)
            )
            # Insecure random
            findings.extend(
                self._check_insecure_random(line, location)
            )
            # Broken auth
            findings.extend(
                self._check_broken_auth(line, location)
            )

        return findings

    def _check_sql_injection(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect SQL injection vulnerabilities."""
        findings: list[RawFinding] = []
        # String formatting in SQL queries
        sql_patterns = [
            r'(?:execute|cursor\.execute|query)\s*\(\s*[f"\'].*%[sd]',
            r'(?:execute|cursor\.execute|query)\s*\(\s*.*\.format\(',
            r'(?:execute|cursor\.execute|query)\s*\(\s*f["\']',
            r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["\']?\s*\+\s*',
            r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*%\s*\(',
        ]
        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="sql-injection",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "injection"},
                ))
                break
        return findings

    def _check_command_injection(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect command injection vulnerabilities."""
        findings: list[RawFinding] = []
        cmd_patterns = [
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'subprocess\.(?:call|run|Popen)\s*\(\s*[f"\']',
            r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True',
            r'exec\s*\(\s*[^)]*(?:input|request|argv)',
            r'eval\s*\(\s*[^)]*(?:input|request|argv)',
        ]
        for pattern in cmd_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="command-injection",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "injection"},
                ))
                break
        return findings

    def _check_xss(self, line: str, location: str) -> list[RawFinding]:
        """Detect cross-site scripting vulnerabilities."""
        findings: list[RawFinding] = []
        xss_patterns = [
            r'innerHTML\s*=\s*[^"\']+(?:input|request|params|query)',
            r'document\.write\s*\(',
            r'\.html\s*\(\s*[^)]*(?:input|request|params|query)',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
            r'\|\s*safe\b',
            r'mark_safe\s*\(',
        ]
        for pattern in xss_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="xss-vulnerability",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "injection"},
                ))
                break
        return findings

    def _check_hardcoded_secrets(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect hardcoded secrets (API keys, passwords, tokens)."""
        findings: list[RawFinding] = []
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            return findings

        secret_patterns = [
            # API keys (generic patterns)
            r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
            # AWS keys
            r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            # Password assignments
            r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
            # Token assignments
            r'(?:token|secret|auth_token|access_token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
            # Private keys
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            # Generic secret patterns
            r'(?:SECRET_KEY|PRIVATE_KEY|JWT_SECRET)\s*[=:]\s*["\'][^"\']+["\']',
        ]
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Mask the actual secret in evidence
                evidence = re.sub(
                    r'(["\'])[A-Za-z0-9_\-\.]{8,}(["\'])',
                    r'\1****REDACTED****\2',
                    line.strip()[:200],
                )
                findings.append(RawFinding(
                    check="hardcoded-secret",
                    category="security",
                    location=location,
                    evidence=evidence,
                    context={"vulnerability_type": "secrets"},
                ))
                break
        return findings

    def _check_insecure_deserialization(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect insecure deserialization patterns."""
        findings: list[RawFinding] = []
        deser_patterns = [
            r'pickle\.loads?\s*\(',
            r'pickle\.Unpickler\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)',
            r'yaml\.unsafe_load\s*\(',
            r'marshal\.loads?\s*\(',
            r'shelve\.open\s*\(',
            r'jsonpickle\.decode\s*\(',
            r'unserialize\s*\(',  # PHP
            r'ObjectInputStream\s*\(',  # Java
            r'readObject\s*\(',  # Java
        ]
        for pattern in deser_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="insecure-deserialization",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "deserialization"},
                ))
                break
        return findings

    def _check_path_traversal(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect path traversal vulnerabilities."""
        findings: list[RawFinding] = []
        path_patterns = [
            r'open\s*\([^)]*(?:request|input|argv|params|query)',
            r'(?:os\.path\.join|Path)\s*\([^)]*(?:request|input|argv|params|query)',
            r'\.\./\.\.',
            r'(?:readFile|readFileSync)\s*\([^)]*(?:req\.|params|query)',
        ]
        for pattern in path_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="path-traversal",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "path-traversal"},
                ))
                break
        return findings

    def _check_insecure_random(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect insecure random number generation for security contexts."""
        findings: list[RawFinding] = []
        # Check for random module usage in security-sensitive contexts
        random_patterns = [
            r'random\.random\s*\(',
            r'random\.randint\s*\(',
            r'random\.choice\s*\(',
            r'random\.randrange\s*\(',
            r'Math\.random\s*\(',
        ]
        security_context_patterns = [
            r'(?:token|secret|key|password|session|auth|csrf|nonce|salt)',
        ]
        for pattern in random_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if line has security context
                for ctx_pattern in security_context_patterns:
                    if re.search(ctx_pattern, line, re.IGNORECASE):
                        findings.append(RawFinding(
                            check="insecure-random",
                            category="security",
                            location=location,
                            evidence=line.strip()[:200],
                            context={
                                "vulnerability_type": "insecure-random",
                                "recommendation": "Use secrets module or os.urandom()",
                            },
                        ))
                        break
                break
        return findings

    def _check_broken_auth(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect broken authentication patterns."""
        findings: list[RawFinding] = []
        # Hardcoded credentials
        cred_patterns = [
            r'(?:username|user)\s*[=:]\s*["\'](?:admin|root|test|user)["\']',
            r'(?:password|passwd)\s*[=:]\s*["\'](?:admin|password|123456|root|test)["\']',
        ]
        for pattern in cred_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="broken-auth-hardcoded-credentials",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "broken-auth"},
                ))
                break

        # Missing token validation
        token_patterns = [
            r'(?:jwt|token).*(?:verify|validate)\s*=\s*False',
            r'algorithms\s*=\s*\[.*none.*\]',
            r'verify_signature\s*=\s*False',
        ]
        for pattern in token_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="broken-auth-missing-validation",
                    category="security",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"vulnerability_type": "broken-auth"},
                ))
                break

        return findings

    # --- Bug Risk Checks ---


    def _check_bug_risks(
        self, source: str, filepath: str
    ) -> list[RawFinding]:
        """Detect null dereferences, uncaught exceptions, race conditions, off-by-one."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"

            # Null/undefined dereference risks
            findings.extend(
                self._check_null_dereference(line, location)
            )
            # Uncaught exceptions
            findings.extend(
                self._check_uncaught_exceptions(line, lines, line_num, location)
            )
            # Race conditions
            findings.extend(
                self._check_race_conditions(line, location)
            )
            # Off-by-one errors
            findings.extend(
                self._check_off_by_one(line, location)
            )

        return findings

    def _check_null_dereference(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect potential null/undefined dereference patterns."""
        findings: list[RawFinding] = []
        null_patterns = [
            # Accessing attribute after potential None return
            (r'\.get\([^)]*\)\.[a-zA-Z]', "medium"),
            # Chained access without null check
            (r'(?:result|response|data|obj|item)\s*\[.*\]\s*\.', "low"),
            # Optional return used without check
            (r'(?:find|search|match)\s*\([^)]*\)\.\w+', "medium"),
            # None comparison followed by usage
            (r'if\s+\w+\s+is\s+not\s+None.*\n.*else.*\.\w+', "high"),
        ]
        for pattern, confidence in null_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="null-dereference",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={
                        "bug_risk_type": BugRiskType.NULL_DEREFERENCE.value,
                        "confidence": confidence,
                    },
                ))
                break
        return findings

    def _check_uncaught_exceptions(
        self, line: str, lines: list[str], line_num: int, location: str
    ) -> list[RawFinding]:
        """Detect uncaught exception paths."""
        findings: list[RawFinding] = []
        # Functions that raise without try/except context
        raise_patterns = [
            (r'raise\s+\w+', "medium"),
            # Bare except that swallows errors
            (r'except\s*:', "low"),
            # Division without zero check
            (r'/\s*(?:int|float)?\s*\([^)]*(?:input|request|argv)', "high"),
        ]
        for pattern, confidence in raise_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if inside a try block (simple heuristic)
                in_try = False
                for prev_line_num in range(max(0, line_num - 10), line_num - 1):
                    if re.search(r'^\s*try\s*:', lines[prev_line_num]):
                        in_try = True
                        break
                if not in_try and "raise" in line:
                    findings.append(RawFinding(
                        check="uncaught-exception",
                        category="bug-risk",
                        location=location,
                        evidence=line.strip()[:200],
                        context={
                            "bug_risk_type": BugRiskType.UNCAUGHT_EXCEPTION.value,
                            "confidence": confidence,
                        },
                    ))
                elif "except" in line and ":" in line:
                    # Bare except swallowing errors
                    if re.match(r'\s*except\s*:', line):
                        findings.append(RawFinding(
                            check="uncaught-exception",
                            category="bug-risk",
                            location=location,
                            evidence=line.strip()[:200],
                            context={
                                "bug_risk_type": BugRiskType.UNCAUGHT_EXCEPTION.value,
                                "confidence": "low",
                            },
                        ))
                break
        return findings

    def _check_race_conditions(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect potential race conditions (shared mutable state)."""
        findings: list[RawFinding] = []
        race_patterns = [
            # Global mutable state access in threaded context
            (r'(?:global|threading\.Thread|multiprocessing)', "medium"),
            # Shared state without lock
            (r'(?:shared_|global_)\w+\s*[=\+\-]', "high"),
            # File operations without locking
            (r'open\s*\([^)]*["\'](?:w|a|r\+)', "low"),
            # Async shared state
            (r'(?:asyncio\.gather|concurrent\.futures)', "low"),
        ]
        for pattern, confidence in race_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="race-condition",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={
                        "bug_risk_type": BugRiskType.RACE_CONDITION.value,
                        "confidence": confidence,
                    },
                ))
                break
        return findings

    def _check_off_by_one(
        self, line: str, location: str
    ) -> list[RawFinding]:
        """Detect potential off-by-one errors in loops and array access."""
        findings: list[RawFinding] = []
        obo_patterns = [
            # <= len() in range (common off-by-one)
            (r'range\s*\(\s*.*,\s*len\s*\(\w+\)\s*\+\s*1\s*\)', "medium"),
            (r'for.*<=\s*(?:len|length|size|count)\s*\(', "high"),
            # Array access with length (arr[len(arr)])
            (r'\w+\[\s*len\s*\(\s*\w+\s*\)\s*\]', "high"),
            (r'\w+\[\s*\w+\.length\s*\]', "high"),
            # Boundary comparison issues
            (r'(?:while|if)\s+\w+\s*<=\s*\w+\.(?:length|size|count)', "medium"),
        ]
        for pattern, confidence in obo_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="off-by-one",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={
                        "bug_risk_type": BugRiskType.OFF_BY_ONE.value,
                        "confidence": confidence,
                    },
                ))
                break
        return findings

    # --- Quality Checks ---


    def _check_quality(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect dead code, duplicated logic, high complexity, magic numbers."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        # Dead code detection
        findings.extend(self._check_dead_code(lines, filepath))
        # Duplicated logic detection
        findings.extend(self._check_duplicated_logic(lines, filepath))
        # Cyclomatic complexity
        findings.extend(self._check_complexity(source, filepath))
        # Magic numbers
        findings.extend(self._check_magic_numbers(lines, filepath))

        return findings

    def _check_dead_code(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect unreachable statements and unused imports/variables."""
        findings: list[RawFinding] = []

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            # Unreachable code after return/break/continue
            if line_num > 1:
                prev_stripped = lines[line_num - 2].strip()
                if prev_stripped in ("return", "break", "continue") or prev_stripped.startswith("return "):
                    # Check if current line is at same or deeper indentation and not empty
                    if stripped and not stripped.startswith(("#", "//", "/*", "*/", "}")):
                        curr_indent = len(line) - len(line.lstrip())
                        prev_indent = len(lines[line_num - 2]) - len(lines[line_num - 2].lstrip())
                        if curr_indent >= prev_indent and not stripped.startswith(("def ", "class ", "elif ", "else:", "except", "finally")):
                            findings.append(RawFinding(
                                check="dead-code",
                                category="quality",
                                location=location,
                                evidence=f"Unreachable code after return/break: {stripped[:100]}",
                                context={"type": "unreachable"},
                            ))

            # Unused imports (Python-specific heuristic)
            import_match = re.match(
                r'^(?:from\s+\S+\s+)?import\s+(.+)', stripped
            )
            if import_match:
                imported_names = import_match.group(1)
                # Handle "import x as y" and "from x import a, b"
                names = []
                for part in imported_names.split(","):
                    part = part.strip()
                    if " as " in part:
                        names.append(part.split(" as ")[-1].strip())
                    else:
                        names.append(part.split(".")[-1].strip())

                # Check if any imported name is used in the rest of the file
                rest_of_file = "\n".join(lines[line_num:])
                for name in names:
                    if name and name != "*":
                        # Simple check: name appears elsewhere in file
                        pattern = r'\b' + re.escape(name) + r'\b'
                        if not re.search(pattern, rest_of_file):
                            findings.append(RawFinding(
                                check="dead-code",
                                category="quality",
                                location=location,
                                evidence=f"Unused import: {name}",
                                context={"type": "unused-import"},
                            ))

        return findings

    def _check_duplicated_logic(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect duplicated logic blocks (>6 consecutive identical lines)."""
        findings: list[RawFinding] = []
        min_duplicate_lines = 7  # More than 6 consecutive lines

        # Normalize lines (strip whitespace, skip empty/comment lines)
        normalized: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(("#", "//", "/*", "*/")):
                normalized.append((i + 1, stripped))

        # Find duplicate blocks
        seen_blocks: dict[str, int] = {}
        i = 0
        while i <= len(normalized) - min_duplicate_lines:
            block_lines = [
                normalized[i + j][1] for j in range(min_duplicate_lines)
            ]
            block_key = "\n".join(block_lines)

            if block_key in seen_blocks:
                first_line = seen_blocks[block_key]
                current_line = normalized[i][0]
                findings.append(RawFinding(
                    check="duplicated-logic",
                    category="quality",
                    location=f"{filepath}:{current_line}",
                    evidence=(
                        f"Duplicated block of {min_duplicate_lines} lines. "
                        f"First occurrence at line {first_line}, "
                        f"duplicate at line {current_line}"
                    ),
                    context={
                        "first_occurrence": first_line,
                        "duplicate_at": current_line,
                        "line_count": min_duplicate_lines,
                    },
                ))
                i += min_duplicate_lines  # Skip past this block
            else:
                seen_blocks[block_key] = normalized[i][0]
                i += 1

        return findings

    def _check_complexity(
        self, source: str, filepath: str
    ) -> list[RawFinding]:
        """Detect functions with cyclomatic complexity > 10."""
        findings: list[RawFinding] = []

        # Find function definitions and calculate complexity
        func_pattern = re.compile(
            r'^(\s*)(?:def|function|async\s+def|async\s+function)\s+(\w+)',
            re.MULTILINE,
        )

        for match in func_pattern.finditer(source):
            func_indent = len(match.group(1))
            func_name = match.group(2)
            func_start = source[:match.start()].count("\n") + 1

            # Extract function body
            func_body = self._extract_function_body(
                source, match.start(), func_indent
            )

            # Count decision points for cyclomatic complexity
            complexity = self._calculate_cyclomatic_complexity(func_body)

            if complexity > 10:
                findings.append(RawFinding(
                    check="high-complexity",
                    category="quality",
                    location=f"{filepath}:{func_start}",
                    evidence=(
                        f"Function '{func_name}' has cyclomatic complexity "
                        f"of {complexity} (threshold: 10)"
                    ),
                    context={
                        "function_name": func_name,
                        "complexity": complexity,
                        "threshold": 10,
                    },
                ))

        return findings

    def _extract_function_body(
        self, source: str, start_pos: int, base_indent: int
    ) -> str:
        """Extract the body of a function starting at start_pos."""
        lines = source[start_pos:].splitlines()
        body_lines: list[str] = []

        # Skip the function definition line
        for i, line in enumerate(lines[1:], start=1):
            if not line.strip():
                body_lines.append(line)
                continue
            current_indent = len(line) - len(line.lstrip())
            if current_indent <= base_indent and line.strip():
                break
            body_lines.append(line)

        return "\n".join(body_lines)

    def _calculate_cyclomatic_complexity(self, func_body: str) -> int:
        """Calculate cyclomatic complexity of a function body.

        Counts decision points: if, elif, for, while, and, or, except,
        case, ternary operators, etc.
        """
        complexity = 1  # Base complexity

        decision_patterns = [
            r'\bif\b',
            r'\belif\b',
            r'\belse\s+if\b',
            r'\bfor\b',
            r'\bwhile\b',
            r'\band\b',
            r'\bor\b',
            r'\b&&\b',
            r'\b\|\|\b',
            r'\bexcept\b',
            r'\bcatch\b',
            r'\bcase\b',
            r'\b\?\s*',  # Ternary
        ]

        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, func_body))

        return complexity

    def _check_magic_numbers(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect magic numbers (excluding 0, 1, -1)."""
        findings: list[RawFinding] = []
        # Pattern for numeric literals that aren't 0, 1, or -1
        magic_pattern = re.compile(
            r'(?<![a-zA-Z_\.])\b(\d+\.?\d*)\b(?!\s*[=:]\s*["\'])'
        )
        excluded_values = {"0", "1", "-1", "0.0", "1.0"}

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments, imports, and constant definitions
            if (
                stripped.startswith(("#", "//", "/*", "*"))
                or "import" in stripped
                or re.match(r'^[A-Z_]+\s*=', stripped)  # CONSTANT = value
                or "def " in stripped
                or "function " in stripped
            ):
                continue

            for match in magic_pattern.finditer(line):
                value = match.group(1)
                if value not in excluded_values:
                    try:
                        num = float(value)
                        if num not in (0, 1, -1, 0.0, 1.0):
                            findings.append(RawFinding(
                                check="magic-number",
                                category="quality",
                                location=f"{filepath}:{line_num}",
                                evidence=(
                                    f"Magic number {value} found: "
                                    f"{stripped[:100]}"
                                ),
                                context={"value": value},
                            ))
                            break  # One finding per line
                    except ValueError:
                        continue

        return findings

    # --- Test Gap Checks ---


    def _check_test_gaps(
        self, source: str, filepath: str, test_files: list[Path]
    ) -> list[RawFinding]:
        """Detect untested branches, weak assertions, missing edge cases, missing test files."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        # Skip if this is a test file itself
        if self._is_test_file(Path(filepath)):
            # Check for weak assertions in test files
            findings.extend(
                self._check_weak_assertions(lines, filepath)
            )
            return findings

        # Check for missing test file
        findings.extend(
            self._check_missing_test_file(filepath, test_files)
        )
        # Check for untested branches
        findings.extend(
            self._check_untested_branches(lines, filepath)
        )
        # Check for missing edge case tests
        findings.extend(
            self._check_missing_edge_cases(lines, filepath)
        )

        return findings

    def _check_weak_assertions(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect weak assertions in test files."""
        findings: list[RawFinding] = []
        weak_patterns = [
            r'assertTrue\s*\(\s*\w+\s*\)',  # assertTrue without value check
            r'assert\s+\w+\s*$',  # bare assert variable
            r'assertIsNotNone\s*\(\s*\w+\s*\)',  # only checks not None
            r'expect\s*\([^)]+\)\.toBeTruthy\s*\(',  # JS toBeTruthy
            r'expect\s*\([^)]+\)\.toBeDefined\s*\(',  # JS toBeDefined
        ]

        for line_num, line in enumerate(lines, start=1):
            for pattern in weak_patterns:
                if re.search(pattern, line):
                    findings.append(RawFinding(
                        check="weak-assertion",
                        category="test-gaps",
                        location=f"{filepath}:{line_num}",
                        evidence=line.strip()[:200],
                        context={
                            "recommendation": "Use specific value assertions",
                        },
                    ))
                    break

        return findings

    def _check_missing_test_file(
        self, filepath: str, test_files: list[Path]
    ) -> list[RawFinding]:
        """Check if a source file has an associated test file."""
        findings: list[RawFinding] = []
        source_path = Path(filepath)
        source_stem = source_path.stem

        # Skip __init__.py and similar
        if source_stem.startswith("__"):
            return findings

        # Look for matching test file patterns
        test_patterns = [
            f"test_{source_stem}",
            f"{source_stem}_test",
            f"{source_stem}.test",
            f"{source_stem}.spec",
        ]

        has_test = any(
            any(pattern in tf.stem.lower() for pattern in test_patterns)
            for tf in test_files
        )

        if not has_test:
            findings.append(RawFinding(
                check="missing-test-file",
                category="test-gaps",
                location=filepath,
                evidence=f"No test file found for {source_path.name}",
                context={
                    "source_file": filepath,
                    "expected_patterns": test_patterns,
                },
            ))

        return findings

    def _check_untested_branches(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect conditional branches that likely lack test coverage."""
        findings: list[RawFinding] = []
        branch_keywords = [
            r'^\s*(?:if|elif|else if)\s+.*:',
            r'^\s*(?:else)\s*:',
            r'^\s*(?:case)\s+',
        ]

        branch_count = 0
        for line_num, line in enumerate(lines, start=1):
            for pattern in branch_keywords:
                if re.match(pattern, line):
                    branch_count += 1
                    break

        # If there are many branches, flag as potentially untested
        if branch_count > 5:
            findings.append(RawFinding(
                check="untested-branches",
                category="test-gaps",
                location=f"{filepath}:1",
                evidence=(
                    f"File contains {branch_count} conditional branches. "
                    f"Ensure adequate test coverage for all paths."
                ),
                context={"branch_count": branch_count},
            ))

        return findings

    def _check_missing_edge_cases(
        self, lines: list[str], filepath: str
    ) -> list[RawFinding]:
        """Detect functions that handle edge cases without corresponding tests."""
        findings: list[RawFinding] = []
        # Look for patterns that suggest edge case handling
        edge_case_patterns = [
            (r'if\s+(?:not\s+)?\w+\s*(?:==|is)\s*(?:None|null|undefined)', "null parameter"),
            (r'if\s+len\s*\(\w+\)\s*==\s*0', "empty input"),
            (r'if\s+\w+\s*(?:<=?|>=?)\s*0', "boundary value"),
            (r'if\s+not\s+\w+', "falsy input"),
        ]

        for line_num, line in enumerate(lines, start=1):
            for pattern, edge_type in edge_case_patterns:
                if re.search(pattern, line):
                    findings.append(RawFinding(
                        check="missing-edge-case-test",
                        category="test-gaps",
                        location=f"{filepath}:{line_num}",
                        evidence=(
                            f"Edge case handling ({edge_type}) at line "
                            f"{line_num}: {line.strip()[:100]}"
                        ),
                        context={"edge_type": edge_type},
                    ))
                    break

        return findings

    # --- Dependency Checks ---


    def _check_dependencies(
        self, source: str, filepath: str
    ) -> list[RawFinding]:
        """Detect typosquatting, deprecated packages, wildcard imports."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            # Check for imports
            import_match = re.match(
                r'^(?:from\s+(\S+)\s+import|import\s+(\S+))', stripped
            )
            if import_match:
                package = import_match.group(1) or import_match.group(2)
                # Get the top-level package name
                top_package = package.split(".")[0]

                # Typosquatting check
                findings.extend(
                    self._check_typosquatting(top_package, location, stripped)
                )
                # Deprecated package check
                findings.extend(
                    self._check_deprecated(top_package, location, stripped)
                )

            # Wildcard import check
            if re.match(r'^from\s+\S+\s+import\s+\*', stripped):
                findings.append(RawFinding(
                    check="wildcard-import",
                    category="dependencies",
                    location=location,
                    evidence=stripped[:200],
                    context={"recommendation": "Use explicit imports"},
                ))

        return findings

    def _check_typosquatting(
        self, package: str, location: str, evidence: str
    ) -> list[RawFinding]:
        """Check if a package name is suspiciously close to a popular package."""
        findings: list[RawFinding] = []
        # Skip if it IS a popular package
        if package.lower() in [p.lower() for p in POPULAR_PACKAGES]:
            return findings

        for popular in POPULAR_PACKAGES:
            distance = self._levenshtein_distance(
                package.lower(), popular.lower()
            )
            if 1 <= distance <= 2:
                findings.append(RawFinding(
                    check="typosquatting-import",
                    category="dependencies",
                    location=location,
                    evidence=(
                        f"Package '{package}' is similar to popular package "
                        f"'{popular}' (edit distance: {distance}). "
                        f"Import: {evidence[:100]}"
                    ),
                    context={
                        "package": package,
                        "similar_to": popular,
                        "distance": distance,
                    },
                ))
                break  # Report only the closest match

        return findings

    def _check_deprecated(
        self, package: str, location: str, evidence: str
    ) -> list[RawFinding]:
        """Check if a package is known to be deprecated."""
        findings: list[RawFinding] = []
        if package.lower() in [p.lower() for p in DEPRECATED_PACKAGES]:
            findings.append(RawFinding(
                check="deprecated-package",
                category="dependencies",
                location=location,
                evidence=f"Deprecated package '{package}': {evidence[:150]}",
                context={"package": package},
            ))
        return findings

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return CodeAnalyzer._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

