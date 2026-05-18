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
from pyqualify.tool_registry import ToolSelector
from pyqualify.utils import resolve_location, truncate_evidence


# Legacy constant kept for backward compatibility
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".rb", ".go",
    ".php", ".cs", ".cpp", ".c", ".h", ".rs", ".swift", ".kt",
}

# Comprehensive language extension map (Task 6.1)
LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++",
    ".cxx": "C++", ".hpp": "C++",
    ".rs": "Rust", ".zig": "Zig", ".asm": "Assembly", ".s": "Assembly",
    ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
    ".groovy": "Groovy", ".gvy": "Groovy", ".scala": "Scala",
    ".clj": "Clojure", ".cljs": "Clojure",
    ".cs": "C#", ".vb": "Visual Basic", ".fs": "F#", ".fsi": "F#",
    ".py": "Python", ".pyw": "Python",
    ".rb": "Ruby", ".rake": "Ruby",
    ".php": "PHP", ".phtml": "PHP",
    ".pl": "Perl", ".pm": "Perl",
    ".lua": "Lua", ".r": "R", ".R": "R",
    ".m": "Objective-C",
    ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hrl": "Erlang",
    ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".mts": "TypeScript",
    ".jsx": "React", ".tsx": "React",
    ".vue": "Vue", ".svelte": "Svelte", ".coffee": "CoffeeScript",
    ".swift": "Swift", ".dart": "Dart",
    ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".bat": "Batch", ".cmd": "Batch",
    ".sql": "SQL",
    ".tf": "Terraform", ".tfvars": "Terraform",
    ".yaml": "YAML", ".yml": "YAML",
    ".go": "Go",
}

# Language-specific security patterns registry (Task 6.2)
SECURITY_PATTERNS: dict[str, dict[str, list[str]]] = {
    "Python": {
        "sql-injection": [
            r'(?:execute|cursor\.execute|query)\s*\(\s*[f"\'].*%[sd]',
            r'(?:execute|cursor\.execute|query)\s*\(\s*.*\.format\(',
            r'(?:execute|cursor\.execute|query)\s*\(\s*f["\']',
        ],
        "command-injection": [
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'subprocess\.(?:call|run|Popen)\s*\(\s*[f"\']',
            r'subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True',
        ],
        "xss-vulnerability": [
            r'mark_safe\s*\(',
            r'\|\s*safe\b',
        ],
        "insecure-deserialization": [
            r'pickle\.loads?\s*\(',
            r'pickle\.Unpickler\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)',
            r'yaml\.unsafe_load\s*\(',
            r'marshal\.loads?\s*\(',
            r'shelve\.open\s*\(',
            r'jsonpickle\.decode\s*\(',
        ],
        "broken-auth-missing-validation": [
            r'(?:jwt|token).*(?:verify|validate)\s*=\s*False',
            r'algorithms\s*=\s*\[.*none.*\]',
            r'verify_signature\s*=\s*False',
        ],
    },
    "Java": {
        "sql-injection": [
            r'Statement\.execute\w*\s*\([^)]*\+',
            r'createStatement\(\)\.execute',
        ],
        "command-injection": [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
            r'ProcessBuilder\s*\(',
        ],
        "xss-vulnerability": [
            r'<%=\s*request\.getParameter\s*\(',
        ],
        "insecure-deserialization": [
            r'ObjectInputStream\s*\(',
            r'readObject\s*\(',
            r'XMLDecoder\s*\(',
        ],
        "broken-auth-missing-validation": [
            r'setVerifySignature\s*\(\s*false\s*\)',
        ],
    },
    "JavaScript": {
        "sql-injection": [
            r'(?:query|execute)\s*\(\s*[`"\'].*\$\{',
            r'(?:query|execute)\s*\(\s*.*\+\s*(?:req\.|params|query)',
        ],
        "command-injection": [
            r'child_process\.exec\s*\(',
            r'child_process\.execSync\s*\(',
        ],
        "xss-vulnerability": [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'dangerouslySetInnerHTML',
        ],
        "insecure-deserialization": [
            r'node-serialize',
        ],
        "broken-auth-missing-validation": [
            r'algorithms\s*:\s*\[.*none.*\]',
            r'ignoreExpiration\s*:\s*true',
        ],
    },
    "TypeScript": {
        "sql-injection": [
            r'(?:query|execute)\s*\(\s*[`"\'].*\$\{',
        ],
        "command-injection": [
            r'child_process\.exec\s*\(',
        ],
        "xss-vulnerability": [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'dangerouslySetInnerHTML',
        ],
        "broken-auth-missing-validation": [
            r'algorithms\s*:\s*\[.*none.*\]',
            r'ignoreExpiration\s*:\s*true',
        ],
    },
    "React": {
        "xss-vulnerability": [
            r'dangerouslySetInnerHTML',
            r'innerHTML\s*=',
        ],
    },
    "Vue": {
        "xss-vulnerability": [
            r'v-html\s*=',
        ],
    },
    "PHP": {
        "sql-injection": [
            r'mysql_query\s*\([^)]*\$_(GET|POST|REQUEST)',
            r'mysqli_query\s*\([^)]*\$_(GET|POST|REQUEST)',
        ],
        "command-injection": [
            r'\bexec\s*\(',
            r'shell_exec\s*\(',
            r'\bsystem\s*\(',
            r'passthru\s*\(',
        ],
        "xss-vulnerability": [
            r'echo\s+\$_(GET|POST|REQUEST)',
        ],
        "insecure-deserialization": [
            r'unserialize\s*\(',
        ],
    },
    "Ruby": {
        "sql-injection": [
            r'ActiveRecord::Base\.connection\.execute\s*\([^)]*#\{',
            r'\.where\s*\(\s*["\'].*#\{',
        ],
        "command-injection": [
            r'`[^`]*#\{',
            r'\bsystem\s*\(',
        ],
        "xss-vulnerability": [
            r'\.html_safe',
            r'\braw\s*\(',
        ],
        "insecure-deserialization": [
            r'Marshal\.load\s*\(',
            r'YAML\.load\s*\([^)]*(?!safe)',
        ],
    },
    "Go": {
        "sql-injection": [
            r'db\.(?:Query|Exec)\s*\([^)]*fmt\.Sprintf',
            r'db\.(?:Query|Exec)\s*\([^)]*\+',
        ],
        "command-injection": [
            r'exec\.Command\s*\([^)]*(?:input|request|param)',
        ],
    },
    "Rust": {
        "sql-injection": [
            r'format!\s*\(\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
        ],
        "command-injection": [
            r'Command::new\s*\([^)]*(?:input|request|param)',
        ],
    },
    "C#": {
        "sql-injection": [
            r'SqlCommand\s*\([^)]*\+',
            r'ExecuteSqlRaw\s*\([^)]*\+',
        ],
        "command-injection": [
            r'Process\.Start\s*\([^)]*(?:input|request|param)',
        ],
        "xss-vulnerability": [
            r'Html\.Raw\s*\(',
        ],
        "insecure-deserialization": [
            r'BinaryFormatter',
            r'TypeNameHandling\.All',
        ],
    },
    "Swift": {
        "command-injection": [
            r'Process\s*\(\).*arguments.*(?:input|request)',
        ],
    },
    "Dart": {
        "command-injection": [
            r'Process\.run\s*\([^)]*(?:input|request)',
        ],
    },
    "Kotlin": {
        "sql-injection": [
            r'createStatement\(\)\.execute',
            r'rawQuery\s*\([^)]*\$',
        ],
        "command-injection": [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
        ],
    },
    "Shell": {
        "command-injection": [
            r'eval\s+',
        ],
    },
    "Elixir": {
        "command-injection": [
            r'System\.cmd\s*\([^)]*(?:input|params)',
        ],
    },
    "Scala": {
        "sql-injection": [
            r'Statement\.execute\w*\s*\([^)]*\+',
        ],
        "command-injection": [
            r'Runtime\.getRuntime\(\)\.exec\s*\(',
        ],
    },
}

# Universal security patterns (apply to all languages)
UNIVERSAL_SECURITY_PATTERNS: dict[str, list[str]] = {
    "sql-injection": [
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["\']?\s*\+\s*',
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*%\s*\(',
    ],
    "hardcoded-secret": [
        r'(?:api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']',
        r'(?:AKIA|ASIA)[A-Z0-9]{16}',
        r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
        r'(?:token|secret|auth_token|access_token)\s*[=:]\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
        r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        r'(?:SECRET_KEY|PRIVATE_KEY|JWT_SECRET)\s*[=:]\s*["\'][^"\']+["\']',
    ],
    "path-traversal": [
        r'\.\./\.\.',
    ],
    "insecure-random": [
        r'random\.random\s*\(',
        r'random\.randint\s*\(',
        r'Math\.random\s*\(',
    ],
    "xss-vulnerability": [
        r'innerHTML\s*=\s*[^"\']+(?:input|request|params|query)',
        r'document\.write\s*\(',
        r'dangerouslySetInnerHTML',
        r'v-html\s*=',
        r'\|\s*safe\b',
        r'mark_safe\s*\(',
    ],
    "broken-auth-hardcoded-credentials": [
        r'(?:username|user)\s*[=:]\s*["\'](?:admin|root|test|user)["\']',
        r'(?:password|passwd)\s*[=:]\s*["\'](?:admin|password|123456|root|test)["\']',
    ],
}

# Import patterns per language (Task 6.3)
IMPORT_PATTERNS: dict[str, list[str]] = {
    "Python": [r'^(?:from\s+(\S+)\s+import|import\s+(\S+))'],
    "JavaScript": [
        r'require\s*\(\s*["\']([^"\']+)["\']',
        r'import\s+.*\s+from\s+["\']([^"\']+)["\']',
    ],
    "TypeScript": [
        r'require\s*\(\s*["\']([^"\']+)["\']',
        r'import\s+.*\s+from\s+["\']([^"\']+)["\']',
    ],
    "React": [
        r'import\s+.*\s+from\s+["\']([^"\']+)["\']',
    ],
    "Java": [r'^import\s+([\w.]+)'],
    "Kotlin": [r'^import\s+([\w.]+)'],
    "Go": [r'import\s+["\']([^"\']+)["\']', r'^\s*["\']([^"\']+)["\']'],
    "Rust": [r'use\s+([\w:]+)', r'extern\s+crate\s+(\w+)'],
    "PHP": [
        r'require(?:_once)?\s+["\']([^"\']+)["\']',
        r'use\s+([\w\\\\]+)',
    ],
    "Ruby": [r'require\s+["\']([^"\']+)["\']'],
    "C#": [r'using\s+([\w.]+)'],
    "Swift": [r'import\s+(\w+)'],
    "Dart": [r'import\s+["\']([^"\']+)["\']'],
    "Elixir": [r'import\s+(\w[\w.]*)'],
    "Scala": [r'import\s+([\w.]+)'],
    "Shell": [r'source\s+([^\s;]+)', r'\.\s+([^\s;]+)'],
}

# Test file conventions per language (Task 6.4)
TEST_FILE_PATTERNS: dict[str, list[str]] = {
    "Python": ["test_", "_test"],
    "JavaScript": [".test.", ".spec.", "__tests__"],
    "TypeScript": [".test.", ".spec.", "__tests__"],
    "React": [".test.", ".spec.", "__tests__"],
    "Java": ["Test.", "Tests.", "Spec."],
    "Go": ["_test."],
    "Rust": ["_test."],
    "PHP": ["Test."],
    "Ruby": ["_spec.", "test_"],
    "C#": ["Tests.", "Test."],
    "Swift": ["Tests."],
    "Kotlin": ["Test.", "Spec."],
    "Dart": ["_test."],
}

# Boilerplate files to skip per language (Task 6.4)
BOILERPLATE_FILES: dict[str, list[str]] = {
    "Python": ["__init__.py", "setup.py", "conftest.py"],
    "JavaScript": ["index.js", "webpack.config.js"],
    "TypeScript": ["index.ts"],
    "Java": ["package-info.java"],
    "Go": ["doc.go"],
    "Rust": ["mod.rs", "lib.rs", "main.rs"],
    "C#": ["AssemblyInfo.cs", "GlobalUsings.cs"],
}

# Popular packages for typosquatting detection (expanded)
POPULAR_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "tensorflow", "pytorch", "scipy", "matplotlib", "sqlalchemy",
    "celery", "redis", "boto3", "pillow", "cryptography",
    "beautifulsoup4", "selenium", "scrapy", "httpx", "pydantic",
    "express", "react", "lodash", "axios", "moment", "webpack",
    "typescript", "jquery", "angular", "vue", "next", "nest",
    "jest", "mocha", "eslint", "prettier",
    "spring-boot", "hibernate", "log4j", "jackson", "guava",
    "gin", "echo", "gorm", "cobra", "viper",
    "tokio", "serde", "actix-web", "reqwest", "clap",
    "rails", "sinatra", "devise", "nokogiri", "rspec",
    "laravel", "symfony", "guzzle", "phpunit",
]

# Known deprecated packages (expanded)
DEPRECATED_PACKAGES = [
    "optparse", "imp", "distutils", "asyncore", "asynchat",
    "formatter", "parser", "symbol", "token", "cgi",
    "request", "querystring", "punycode",
]


# Known vulnerable packages with CVE references (not exhaustive, covers high-profile cases)
KNOWN_VULNERABLE_PACKAGES: dict[str, str] = {
    # Python
    "pyyaml": "CVE-2017-18342 (arbitrary code execution via yaml.load)",
    "pillow": "CVE-2021-25287 (heap buffer overflow in TIFF decoding)",
    "requests": "CVE-2023-32681 (proxy credential leakage via Proxy-Authorization)",
    "urllib3": "CVE-2023-43804 (cookie leakage via redirect)",
    "cryptography": "CVE-2023-49083 (NULL pointer dereference in PKCS12)",
    "paramiko": "CVE-2023-48795 (Terrapin SSH prefix truncation attack)",
    "werkzeug": "CVE-2023-46136 (DoS via multipart/form-data parsing)",
    "flask": "CVE-2023-30861 (cookie leakage via response caching)",
    "django": "CVE-2024-27351 (ReDoS in django.utils.text.Truncator)",
    "sqlalchemy": "CVE-2019-7164 (SQL injection via order_by)",
    "jinja2": "CVE-2024-34064 (XSS via xmlattr filter)",
    "aiohttp": "CVE-2024-23334 (path traversal in static file serving)",
    "starlette": "CVE-2023-29159 (path traversal in StaticFiles)",
    "fastapi": "CVE-2024-24762 (ReDoS via multipart/form-data)",
    # JavaScript / Node
    "lodash": "CVE-2021-23337 (command injection via template)",
    "axios": "CVE-2023-45857 (CSRF via cross-site request forgery)",
    "moment": "CVE-2022-24785 (path traversal in locale loading)",
    "express": "CVE-2022-24999 (open redirect via qs prototype pollution)",
    "jsonwebtoken": "CVE-2022-23529 (arbitrary file write via secretOrPublicKey)",
    "node-fetch": "CVE-2022-0235 (exposure of sensitive information to unauthorized actor)",
    "minimist": "CVE-2021-44906 (prototype pollution)",
    "qs": "CVE-2022-24999 (prototype pollution)",
    "semver": "CVE-2022-25883 (ReDoS)",
    "tough-cookie": "CVE-2023-26136 (prototype pollution)",
    "word-wrap": "CVE-2023-26115 (ReDoS)",
    # Java
    "log4j": "CVE-2021-44228 (Log4Shell - remote code execution via JNDI lookup)",
    "log4j-core": "CVE-2021-44228 (Log4Shell - remote code execution via JNDI lookup)",
    "spring-core": "CVE-2022-22965 (Spring4Shell - remote code execution)",
    "jackson-databind": "CVE-2022-42003 (deep wrapper array nesting DoS)",
    "commons-text": "CVE-2022-42889 (Text4Shell - remote code execution)",
    "commons-collections": "CVE-2015-6420 (Java deserialization remote code execution)",
    "xstream": "CVE-2021-39144 (remote code execution via deserialization)",
    "struts2": "CVE-2023-50164 (path traversal leading to RCE)",
    # Ruby
    "rails": "CVE-2023-22795 (ReDoS in Accept header parsing)",
    "nokogiri": "CVE-2022-24836 (ReDoS in HTML encoding detection)",
    "rack": "CVE-2022-44571 (ReDoS in multipart boundary parsing)",
    # PHP
    "guzzle": "CVE-2022-31090 (SSRF via change in port to standard port)",
    "symfony": "CVE-2022-24894 (cookie leakage via HttpCache)",
    # Go
    "golang.org/x/net": "CVE-2022-41723 (HTTP/2 rapid reset attack)",
    "golang.org/x/crypto": "CVE-2020-29652 (nil pointer dereference in SSH)",
}


class CodeAnalyzer:
    """Analyzes source code for security, quality, bugs, tests, and dependencies."""

    def __init__(self, ai_engine: AIEngineProtocol, logger: PyqualifyLogger) -> None:
        self._ai_engine = ai_engine
        self._logger = logger
        self._scoring = ScoringEngine()

    def _detect_language(self, filepath: str) -> str:
        """Detect language from file extension. Returns 'unknown' if unrecognized."""
        ext = Path(filepath).suffix.lower()
        return LANGUAGE_EXTENSIONS.get(ext, "unknown")

    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:
        """Run analysis on the given target path and return structured results."""
        self._logger.info("code_analyzer", f"Starting code analysis on: {target}")
        target_path = Path(target)
        all_findings: list[RawFinding] = []

        # Merge user-provided extra extensions (Task 6.7)
        extra_exts = getattr(config, "extra_extensions", None) or []
        active_extensions = set(LANGUAGE_EXTENSIONS.keys())
        for ext in extra_exts:
            if not ext.startswith("."):
                ext = f".{ext}"
            active_extensions.add(ext)

        code_files = self._collect_code_files(target_path, active_extensions)
        test_files = [f for f in code_files if self._is_test_file(f)]

        # Build tool selector from config
        tool_selector = ToolSelector.from_config("code", config)

        self._logger.info(
            "code_analyzer",
            f"Found {len(code_files)} code files, {len(test_files)} test files",
        )
        if tool_selector.only or tool_selector.exclude:
            self._logger.info(
                "code_analyzer",
                f"Enabled tools: {tool_selector.get_enabled_tools()}",
            )

        for filepath in code_files:
            try:
                source = filepath.read_text(encoding="utf-8", errors="replace")
            except (OSError, IOError) as e:
                self._logger.warning("code_analyzer", f"Cannot read file {filepath}: {e}")
                continue

            file_str = str(filepath)
            language = self._detect_language(file_str)
            try:
                findings = self._analyze_single_file(source, file_str, test_files, language, tool_selector)
                all_findings.extend(findings)
            except Exception as e:
                self._logger.warning("code_analyzer", f"Parse error in {filepath}: {e}. Skipping file.")
                continue

        context = AnalysisContext(
            mode=AnalysisMode.CODE,
            target=target,
            additional_context={"file_count": len(code_files)},
        )

        self._logger.info("code_analyzer", f"Processing {len(all_findings)} raw findings through AI engine")
        issues = await self._ai_engine.process_findings(all_findings, context)

        for issue in issues:
            issue.evidence = truncate_evidence(issue.evidence)

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
            score=score, grade=grade, risk_level=risk_level,
            issues=issues, summary=summary, metadata=metadata,
        )

        self._logger.info(
            "code_analyzer",
            f"Analysis complete. Score: {score}, Grade: {grade}, "
            f"Risk: {risk_level.value}, Issues: {len(issues)}",
        )
        return result

    def _collect_code_files(self, target_path: Path, active_extensions: set[str] | None = None) -> list[Path]:
        """Collect all code files from target path (file or directory)."""
        extensions = active_extensions or set(LANGUAGE_EXTENSIONS.keys())
        if target_path.is_file():
            if target_path.suffix in extensions:
                return [target_path]
            return []

        code_files: list[Path] = []
        if target_path.is_dir():
            for root, _dirs, files in os.walk(target_path):
                root_path = Path(root)
                if any(
                    part.startswith(".")
                    or part in ("node_modules", "__pycache__", "venv", ".venv", "dist", "build")
                    for part in root_path.parts
                ):
                    continue
                for filename in files:
                    file_path = root_path / filename
                    if file_path.suffix in extensions:
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
        self, source: str, filepath: str, test_files: list[Path], language: str = "unknown",
        tool_selector: ToolSelector | None = None,
    ) -> list[RawFinding]:
        """Run all checks on a single source file."""
        findings: list[RawFinding] = []
        ts = tool_selector or ToolSelector(category="code")

        if ts.is_enabled("security"):
            findings.extend(self._check_security(source, filepath, language))
        if ts.is_enabled("bug-risks"):
            findings.extend(self._check_bug_risks(source, filepath))
        if ts.is_enabled("quality"):
            findings.extend(self._check_quality(source, filepath, language))
        if ts.is_enabled("test-gaps"):
            findings.extend(self._check_test_gaps(source, filepath, test_files, language))
        if ts.is_enabled("dependencies"):
            findings.extend(self._check_dependencies(source, filepath, language))
        if ts.is_enabled("audit-log"):
            findings.extend(self._check_audit_log(source, filepath))
        if ts.is_enabled("case-sensitivity"):
            findings.extend(self._check_case_sensitivity(source, filepath))
        if ts.is_enabled("known-vulnerabilities"):
            findings.extend(self._check_known_vulnerabilities(source, filepath, language))
        if ts.is_enabled("password-policy"):
            findings.extend(self._check_password_policy(source, filepath))
        return findings

    # --- Security Checks (Task 6.2 - Language-aware) ---

    def _check_security(self, source: str, filepath: str, language: str = "unknown") -> list[RawFinding]:
        """Detect injection vulnerabilities, hardcoded secrets, insecure patterns."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        # Auto-detect language from filepath if not provided
        if language == "unknown":
            language = self._detect_language(filepath)

        # Get language-specific patterns
        lang_patterns = SECURITY_PATTERNS.get(language, {})

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check language-specific patterns
            for check_name, patterns in lang_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(RawFinding(
                            check=check_name,
                            category="security",
                            location=location,
                            evidence=line.strip()[:200],
                            context={"vulnerability_type": check_name, "language": language},
                        ))
                        break

            # Check universal patterns
            for check_name, patterns in UNIVERSAL_SECURITY_PATTERNS.items():
                if check_name == "hardcoded-secret":
                    if stripped.startswith("#") or stripped.startswith("//"):
                        continue
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
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
                elif check_name == "insecure-random":
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            security_ctx = r'(?:token|secret|key|password|session|auth|csrf|nonce|salt)'
                            if re.search(security_ctx, line, re.IGNORECASE):
                                findings.append(RawFinding(
                                    check="insecure-random",
                                    category="security",
                                    location=location,
                                    evidence=line.strip()[:200],
                                    context={"vulnerability_type": "insecure-random"},
                                ))
                            break
                else:
                    for pattern in patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(RawFinding(
                                check=check_name,
                                category="security",
                                location=location,
                                evidence=line.strip()[:200],
                                context={"vulnerability_type": check_name},
                            ))
                            break

            # Path traversal with user input
            path_patterns = [
                r'open\s*\([^)]*(?:request|input|argv|params|query)',
                r'(?:os\.path\.join|Path)\s*\([^)]*(?:request|input|argv|params|query)',
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

    # --- Task 1: Audit Log Manipulation ---

    def _check_audit_log(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect log injection, log suppression, and audit log deletion patterns."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            # Log injection: unsanitized user input in log calls
            log_injection_patterns = [
                r'(?:logging|logger)\.\w+\s*\(\s*f["\'].*(?:request|user_input|params)',
                r'(?:logging|logger)\.\w+\s*\([^)]*(?:request\.|user_input|params\[)',
                r'(?:log|logger)\.\w+\s*\(\s*.*\+\s*(?:request|user_input|params)',
            ]
            for pattern in log_injection_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(RawFinding(
                        check="log-injection",
                        category="security",
                        location=location,
                        evidence=stripped[:200],
                        context={"vulnerability_type": "audit-log-manipulation"},
                    ))
                    break

            # Log suppression: bare except blocks that swallow without logging
            if re.match(r'\s*except\s*:', line):
                # Check next few lines for logging
                has_logging = False
                for next_line in lines[line_num:min(line_num + 5, len(lines))]:
                    if re.search(r'(?:logging|logger|log)\.\w+', next_line):
                        has_logging = True
                        break
                if not has_logging:
                    findings.append(RawFinding(
                        check="log-suppression",
                        category="security",
                        location=location,
                        evidence=f"Bare except block without logging: {stripped[:100]}",
                        context={"vulnerability_type": "audit-log-manipulation"},
                    ))

            # Audit log deletion: removing or overwriting log files
            log_deletion_patterns = [
                r'os\.remove\s*\([^)]*(?:log|\.log)',
                r'os\.unlink\s*\([^)]*(?:log|\.log)',
                r'open\s*\([^)]*(?:log|\.log)[^)]*["\']w["\']',
                r'shutil\.rmtree\s*\([^)]*log',
            ]
            for pattern in log_deletion_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(RawFinding(
                        check="audit-log-deletion",
                        category="security",
                        location=location,
                        evidence=stripped[:200],
                        context={"vulnerability_type": "audit-log-manipulation"},
                    ))
                    break

            # Disabled logging
            if re.search(r'logging\.disable\s*\(\s*logging\.CRITICAL', line):
                findings.append(RawFinding(
                    check="log-suppression",
                    category="security",
                    location=location,
                    evidence=stripped[:200],
                    context={"vulnerability_type": "audit-log-manipulation"},
                ))

        return findings

    # --- Task 4: Case Sensitivity Check in Code ---

    def _check_case_sensitivity(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect string comparisons missing case normalization for auth/routing."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        case_patterns = [
            r'if\s+\w*(?:username|user|role|email|path|route)\w*\s*==\s*["\']',
            r'if\s+["\'].*["\']\s*==\s*\w*(?:username|user|role|email|path|route)',
        ]

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            for pattern in case_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Check if .lower() or .casefold() is used
                    if not re.search(r'\.(?:lower|casefold|upper)\s*\(\)', line):
                        findings.append(RawFinding(
                            check="case-insensitive-comparison-missing",
                            category="security",
                            location=location,
                            evidence=line.strip()[:200],
                            context={"vulnerability_type": "case-sensitivity"},
                        ))
                    break

        return findings

    # --- Bug Risk Checks ---

    def _check_bug_risks(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect null dereferences, uncaught exceptions, race conditions, off-by-one."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            findings.extend(self._check_null_dereference(line, location))
            findings.extend(self._check_uncaught_exceptions(line, lines, line_num, location))
            findings.extend(self._check_race_conditions(line, location))
            findings.extend(self._check_off_by_one(line, location))

        return findings

    def _check_null_dereference(self, line: str, location: str) -> list[RawFinding]:
        """Detect potential null/undefined dereference patterns."""
        findings: list[RawFinding] = []
        null_patterns = [
            (r'\.get\([^)]*\)\.[a-zA-Z]', "medium"),
            (r'(?:result|response|data|obj|item)\s*\[.*\]\s*\.', "low"),
            (r'(?:find|search|match)\s*\([^)]*\)\.\w+', "medium"),
        ]
        for pattern, confidence in null_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="null-dereference",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"bug_risk_type": BugRiskType.NULL_DEREFERENCE.value, "confidence": confidence},
                ))
                break
        return findings

    def _check_uncaught_exceptions(
        self, line: str, lines: list[str], line_num: int, location: str
    ) -> list[RawFinding]:
        """Detect uncaught exception paths."""
        findings: list[RawFinding] = []
        raise_patterns = [
            (r'raise\s+\w+', "medium"),
            (r'except\s*:', "low"),
            (r'/\s*(?:int|float)?\s*\([^)]*(?:input|request|argv)', "high"),
        ]
        for pattern, confidence in raise_patterns:
            if re.search(pattern, line, re.IGNORECASE):
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
                        context={"bug_risk_type": BugRiskType.UNCAUGHT_EXCEPTION.value, "confidence": confidence},
                    ))
                elif "except" in line and ":" in line:
                    if re.match(r'\s*except\s*:', line):
                        findings.append(RawFinding(
                            check="uncaught-exception",
                            category="bug-risk",
                            location=location,
                            evidence=line.strip()[:200],
                            context={"bug_risk_type": BugRiskType.UNCAUGHT_EXCEPTION.value, "confidence": "low"},
                        ))
                break
        return findings

    def _check_race_conditions(self, line: str, location: str) -> list[RawFinding]:
        """Detect potential race conditions (shared mutable state)."""
        findings: list[RawFinding] = []
        race_patterns = [
            (r'(?:global|threading\.Thread|multiprocessing)', "medium"),
            (r'(?:shared_|global_)\w+\s*[=\+\-]', "high"),
            (r'open\s*\([^)]*["\'](?:w|a|r\+)', "low"),
            (r'(?:asyncio\.gather|concurrent\.futures)', "low"),
        ]
        for pattern, confidence in race_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="race-condition",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"bug_risk_type": BugRiskType.RACE_CONDITION.value, "confidence": confidence},
                ))
                break
        return findings

    def _check_off_by_one(self, line: str, location: str) -> list[RawFinding]:
        """Detect potential off-by-one errors in loops and array access."""
        findings: list[RawFinding] = []
        obo_patterns = [
            (r'range\s*\(\s*.*,\s*len\s*\(\w+\)\s*\+\s*1\s*\)', "medium"),
            (r'for.*<=\s*(?:len|length|size|count)\s*\(', "high"),
            (r'\w+\[\s*len\s*\(\s*\w+\s*\)\s*\]', "high"),
            (r'\w+\[\s*\w+\.length\s*\]', "high"),
            (r'(?:while|if)\s+\w+\s*<=\s*\w+\.(?:length|size|count)', "medium"),
        ]
        for pattern, confidence in obo_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append(RawFinding(
                    check="off-by-one",
                    category="bug-risk",
                    location=location,
                    evidence=line.strip()[:200],
                    context={"bug_risk_type": BugRiskType.OFF_BY_ONE.value, "confidence": confidence},
                ))
                break
        return findings

    # --- Quality Checks ---

    def _check_quality(self, source: str, filepath: str, language: str = "unknown") -> list[RawFinding]:
        """Detect dead code, duplicated logic, high complexity, magic numbers."""
        findings: list[RawFinding] = []
        lines = source.splitlines()
        findings.extend(self._check_dead_code(lines, filepath, language))
        findings.extend(self._check_duplicated_logic(lines, filepath))
        findings.extend(self._check_complexity(source, filepath))
        findings.extend(self._check_magic_numbers(lines, filepath))
        return findings

    def _check_dead_code(self, lines: list[str], filepath: str, language: str = "unknown") -> list[RawFinding]:
        """Detect unreachable statements and unused imports/variables."""
        findings: list[RawFinding] = []

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            # Unreachable code after return/break/continue
            if line_num > 1:
                prev_stripped = lines[line_num - 2].strip()
                if prev_stripped in ("return", "break", "continue") or prev_stripped.startswith("return "):
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

            # Language-aware unused import detection (Task 6.5)
            import_patterns = IMPORT_PATTERNS.get(language, IMPORT_PATTERNS.get("Python", []))
            for imp_pattern in import_patterns:
                import_match = re.match(imp_pattern, stripped)
                if import_match:
                    groups = [g for g in import_match.groups() if g]
                    if groups:
                        imported_name = groups[0]
                        # Get the short name
                        if "." in imported_name:
                            short_name = imported_name.split(".")[-1]
                        elif "/" in imported_name:
                            short_name = imported_name.split("/")[-1]
                        else:
                            short_name = imported_name
                        # Handle aliases
                        if " as " in stripped:
                            short_name = stripped.split(" as ")[-1].strip().rstrip(";")
                        rest_of_file = "\n".join(lines[line_num:])
                        if short_name and short_name != "*":
                            pattern = r'\b' + re.escape(short_name) + r'\b'
                            if not re.search(pattern, rest_of_file):
                                findings.append(RawFinding(
                                    check="dead-code",
                                    category="quality",
                                    location=location,
                                    evidence=f"Unused import: {short_name}",
                                    context={"type": "unused-import"},
                                ))
                    break

        return findings

    def _check_duplicated_logic(self, lines: list[str], filepath: str) -> list[RawFinding]:
        """Detect duplicated logic blocks (>6 consecutive identical lines)."""
        findings: list[RawFinding] = []
        min_duplicate_lines = 7

        normalized: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith(("#", "//", "/*", "*/")):
                normalized.append((i + 1, stripped))

        seen_blocks: dict[str, int] = {}
        i = 0
        while i <= len(normalized) - min_duplicate_lines:
            block_lines = [normalized[i + j][1] for j in range(min_duplicate_lines)]
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
                        f"First occurrence at line {first_line}, duplicate at line {current_line}"
                    ),
                    context={"first_occurrence": first_line, "duplicate_at": current_line, "line_count": min_duplicate_lines},
                ))
                i += min_duplicate_lines
            else:
                seen_blocks[block_key] = normalized[i][0]
                i += 1
        return findings

    def _check_complexity(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect functions with cyclomatic complexity > 10."""
        findings: list[RawFinding] = []
        func_pattern = re.compile(
            r'^(\s*)(?:def|function|async\s+def|async\s+function)\s+(\w+)',
            re.MULTILINE,
        )
        for match in func_pattern.finditer(source):
            func_indent = len(match.group(1))
            func_name = match.group(2)
            func_start = source[:match.start()].count("\n") + 1
            func_body = self._extract_function_body(source, match.start(), func_indent)
            complexity = self._calculate_cyclomatic_complexity(func_body)
            if complexity > 10:
                findings.append(RawFinding(
                    check="high-complexity",
                    category="quality",
                    location=f"{filepath}:{func_start}",
                    evidence=f"Function '{func_name}' has cyclomatic complexity of {complexity} (threshold: 10)",
                    context={"function_name": func_name, "complexity": complexity, "threshold": 10},
                ))
        return findings

    def _extract_function_body(self, source: str, start_pos: int, base_indent: int) -> str:
        """Extract the body of a function starting at start_pos."""
        lines = source[start_pos:].splitlines()
        body_lines: list[str] = []
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
        """Calculate cyclomatic complexity of a function body."""
        complexity = 1
        decision_patterns = [
            r'\bif\b', r'\belif\b', r'\belse\s+if\b', r'\bfor\b',
            r'\bwhile\b', r'\band\b', r'\bor\b', r'\b&&\b', r'\b\|\|\b',
            r'\bexcept\b', r'\bcatch\b', r'\bcase\b', r'\b\?\s*',
        ]
        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, func_body))
        return complexity

    def _check_magic_numbers(self, lines: list[str], filepath: str) -> list[RawFinding]:
        """Detect magic numbers (excluding 0, 1, -1)."""
        findings: list[RawFinding] = []
        magic_pattern = re.compile(r'(?<![a-zA-Z_\.])\b(\d+\.?\d*)\b(?!\s*[=:]\s*["\'])')
        excluded_values = {"0", "1", "-1", "0.0", "1.0"}

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if (
                stripped.startswith(("#", "//", "/*", "*"))
                or "import" in stripped
                or re.match(r'^[A-Z_]+\s*=', stripped)
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
                                evidence=f"Magic number {value} found: {stripped[:100]}",
                                context={"value": value},
                            ))
                            break
                    except ValueError:
                        continue
        return findings

    # --- Test Gap Checks (Task 6.4 - Language-aware) ---

    def _check_test_gaps(
        self, source: str, filepath: str, test_files: list[Path], language: str = "unknown"
    ) -> list[RawFinding]:
        """Detect untested branches, weak assertions, missing edge cases, missing test files."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        if self._is_test_file(Path(filepath)):
            findings.extend(self._check_weak_assertions(lines, filepath))
            return findings

        # Skip boilerplate files
        filename = Path(filepath).name
        boilerplate = BOILERPLATE_FILES.get(language, [])
        if filename in boilerplate:
            return findings

        findings.extend(self._check_missing_test_file(filepath, test_files, language))
        findings.extend(self._check_untested_branches(lines, filepath))
        findings.extend(self._check_missing_edge_cases(lines, filepath))
        return findings

    def _check_weak_assertions(self, lines: list[str], filepath: str) -> list[RawFinding]:
        """Detect weak assertions in test files."""
        findings: list[RawFinding] = []
        weak_patterns = [
            r'assertTrue\s*\(\s*\w+\s*\)',
            r'assert\s+\w+\s*$',
            r'assertIsNotNone\s*\(\s*\w+\s*\)',
            r'expect\s*\([^)]+\)\.toBeTruthy\s*\(',
            r'expect\s*\([^)]+\)\.toBeDefined\s*\(',
        ]
        for line_num, line in enumerate(lines, start=1):
            for pattern in weak_patterns:
                if re.search(pattern, line):
                    findings.append(RawFinding(
                        check="weak-assertion",
                        category="test-gaps",
                        location=f"{filepath}:{line_num}",
                        evidence=line.strip()[:200],
                        context={"recommendation": "Use specific value assertions"},
                    ))
                    break
        return findings

    def _check_missing_test_file(
        self, filepath: str, test_files: list[Path], language: str = "unknown"
    ) -> list[RawFinding]:
        """Check if a source file has an associated test file."""
        findings: list[RawFinding] = []
        source_path = Path(filepath)
        source_stem = source_path.stem

        # Skip boilerplate
        boilerplate = BOILERPLATE_FILES.get(language, [])
        if source_path.name in boilerplate:
            return findings

        test_patterns = [
            f"test_{source_stem}",
            f"{source_stem}_test",
            f"{source_stem}.test",
            f"{source_stem}.spec",
            f"{source_stem}Test",
            f"{source_stem}Tests",
            f"{source_stem}Spec",
        ]

        has_test = any(
            any(pattern.lower() in tf.stem.lower() for pattern in test_patterns)
            for tf in test_files
        )

        if not has_test:
            findings.append(RawFinding(
                check="missing-test-file",
                category="test-gaps",
                location=filepath,
                evidence=f"No test file found for {source_path.name}",
                context={"source_file": filepath, "expected_patterns": test_patterns},
            ))
        return findings

    def _check_untested_branches(self, lines: list[str], filepath: str) -> list[RawFinding]:
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
        if branch_count > 5:
            findings.append(RawFinding(
                check="untested-branches",
                category="test-gaps",
                location=f"{filepath}:1",
                evidence=f"File contains {branch_count} conditional branches. Ensure adequate test coverage.",
                context={"branch_count": branch_count},
            ))
        return findings

    def _check_missing_edge_cases(self, lines: list[str], filepath: str) -> list[RawFinding]:
        """Detect functions that handle edge cases without corresponding tests."""
        findings: list[RawFinding] = []
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
                        evidence=f"Edge case handling ({edge_type}) at line {line_num}: {line.strip()[:100]}",
                        context={"edge_type": edge_type},
                    ))
                    break
        return findings

    # --- Dependency Checks (Task 6.3 - Language-aware) ---

    def _check_dependencies(
        self, source: str, filepath: str, language: str = "unknown"
    ) -> list[RawFinding]:
        """Detect typosquatting, deprecated packages, wildcard imports."""
        findings: list[RawFinding] = []
        lines = source.splitlines()

        # Auto-detect language from filepath if not provided
        if language == "unknown":
            language = self._detect_language(filepath)

        import_pats = IMPORT_PATTERNS.get(language, IMPORT_PATTERNS.get("Python", []))

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            for imp_pattern in import_pats:
                import_match = re.match(imp_pattern, stripped)
                if import_match:
                    groups = [g for g in import_match.groups() if g]
                    if groups:
                        package = groups[0]
                        top_package = package.split(".")[0].split("/")[0]
                        findings.extend(self._check_typosquatting(top_package, location, stripped))
                        findings.extend(self._check_deprecated(top_package, location, stripped))
                    break

            # Wildcard import check (Python)
            if re.match(r'^from\s+\S+\s+import\s+\*', stripped):
                findings.append(RawFinding(
                    check="wildcard-import",
                    category="dependencies",
                    location=location,
                    evidence=stripped[:200],
                    context={"recommendation": "Use explicit imports"},
                ))

        return findings

    def _check_typosquatting(self, package: str, location: str, evidence: str) -> list[RawFinding]:
        """Check if a package name is suspiciously close to a popular package."""
        findings: list[RawFinding] = []
        if package.lower() in [p.lower() for p in POPULAR_PACKAGES]:
            return findings
        for popular in POPULAR_PACKAGES:
            distance = CodeAnalyzer._levenshtein_distance(package.lower(), popular.lower())
            if 1 <= distance <= 2:
                findings.append(RawFinding(
                    check="typosquatting-import",
                    category="dependencies",
                    location=location,
                    evidence=(
                        f"Package '{package}' is similar to popular package "
                        f"'{popular}' (edit distance: {distance}). "
                        f"Possible typosquatting."
                    ),
                    context={"package": package, "similar_to": popular, "distance": distance},
                ))
                break
        return findings

    def _check_deprecated(self, package: str, location: str, evidence: str) -> list[RawFinding]:
        """Check if a package is deprecated."""
        findings: list[RawFinding] = []
        if package.lower() in [d.lower() for d in DEPRECATED_PACKAGES]:
            findings.append(RawFinding(
                check="deprecated-package",
                category="dependencies",
                location=location,
                evidence=f"Package '{package}' is deprecated: {evidence[:150]}",
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
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    # --- Known Vulnerable Packages ---

    def _check_known_vulnerabilities(
        self, source: str, filepath: str, language: str = "unknown"
    ) -> list[RawFinding]:
        """Detect imports of packages with known CVEs.

        Checks imported package names against a registry of packages with
        publicly disclosed vulnerabilities.
        """
        findings: list[RawFinding] = []
        lines = source.splitlines()

        if language == "unknown":
            language = self._detect_language(filepath)

        import_pats = IMPORT_PATTERNS.get(language, IMPORT_PATTERNS.get("Python", []))

        for line_num, line in enumerate(lines, start=1):
            location = f"{filepath}:{line_num}"
            stripped = line.strip()

            for imp_pattern in import_pats:
                import_match = re.match(imp_pattern, stripped)
                if import_match:
                    groups = [g for g in import_match.groups() if g]
                    if groups:
                        package = groups[0]
                        top_package = package.split(".")[0].split("/")[0].lower()
                        cve_info = KNOWN_VULNERABLE_PACKAGES.get(top_package)
                        if cve_info:
                            findings.append(RawFinding(
                                check="known-vulnerable-package",
                                category="dependencies",
                                location=location,
                                evidence=(
                                    f"Package '{top_package}' has known vulnerability: {cve_info}. "
                                    f"Verify you are using a patched version."
                                ),
                                context={
                                    "package": top_package,
                                    "cve_info": cve_info,
                                    "vulnerability_type": "known-cve",
                                    "severity_hint": "high",
                                },
                            ))
                    break

        return findings

    # --- Weak Password Policy ---

    def _check_password_policy(self, source: str, filepath: str) -> list[RawFinding]:
        """Detect missing or weak password policy enforcement in authentication code.

        Looks for password validation logic that lacks minimum length, complexity
        requirements, or uses trivially weak thresholds.
        """
        findings: list[RawFinding] = []
        lines = source.splitlines()

        # Patterns that suggest password validation is happening
        password_validation_patterns = [
            r'(?:password|passwd|pwd).*(?:len|length|size)\s*[<>]=?\s*\d+',
            r'(?:len|length|size)\s*\([^)]*(?:password|passwd|pwd)',
            r'(?:validate|check|verify).*password',
            r'password.*(?:valid|check|verify)',
            r'(?:min|max).*(?:password|passwd).*(?:length|len)',
        ]

        # Patterns indicating weak thresholds (< 8 chars)
        weak_length_pattern = re.compile(
            r'(?:password|passwd|pwd).*(?:len|length)\s*[<>]=?\s*([1-7])\b'
            r'|(?:len|length)\s*\([^)]*(?:password|passwd|pwd)[^)]*\)\s*[<>]=?\s*([1-7])\b',
            re.IGNORECASE,
        )

        # Patterns indicating no complexity check (no uppercase/digit/special char requirement)
        complexity_patterns = [
            r'(?:password|passwd|pwd).*(?:upper|lower|digit|special|symbol|number)',
            r'(?:upper|lower|digit|special|symbol|number).*(?:password|passwd|pwd)',
            r'[A-Z].*password|password.*[A-Z]',
            r'(?:re\.search|re\.match|re\.compile).*(?:password|passwd)',
        ]

        has_password_validation = False
        has_complexity_check = False
        weak_threshold_lines: list[tuple[int, str]] = []

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//")):
                continue

            # Check if this file does password validation
            for pattern in password_validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_password_validation = True
                    break

            # Check for weak length threshold
            weak_match = weak_length_pattern.search(line)
            if weak_match:
                threshold = weak_match.group(1) or weak_match.group(2)
                weak_threshold_lines.append((line_num, threshold or "?"))

            # Check for complexity enforcement
            for pattern in complexity_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    has_complexity_check = True
                    break

        # Report weak thresholds
        for line_num, threshold in weak_threshold_lines:
            findings.append(RawFinding(
                check="weak-password-length-policy",
                category="security",
                location=f"{filepath}:{line_num}",
                evidence=(
                    f"Password length threshold of {threshold} characters is below "
                    f"the recommended minimum of 8. Weak passwords increase brute-force risk."
                ),
                context={
                    "threshold": threshold,
                    "recommended_minimum": 8,
                    "vulnerability_type": "weak-password-policy",
                    "severity_hint": "medium",
                },
            ))

        # Report missing complexity check when password validation exists
        if has_password_validation and not has_complexity_check:
            findings.append(RawFinding(
                check="missing-password-complexity-policy",
                category="security",
                location=filepath,
                evidence=(
                    f"Password validation found but no complexity requirements detected "
                    f"(uppercase, digits, special characters). Weak passwords may be accepted."
                ),
                context={
                    "vulnerability_type": "weak-password-policy",
                    "severity_hint": "low",
                },
            ))

        return findings
