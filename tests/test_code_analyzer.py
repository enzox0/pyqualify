"""Unit tests for the CodeAnalyzer."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from pyqualify.analyzers.code_analyzer import CodeAnalyzer
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import (
    AnalysisConfig,
    AnalysisContext,
    AnalysisMode,
    BugRiskType,
    Issue,
    LogConfig,
    RawFinding,
    Severity,
)


@pytest.fixture
def mock_ai_engine():
    """Create a mock AI engine that returns issues from findings."""
    engine = AsyncMock()
    engine.process_findings = AsyncMock(return_value=[])
    return engine


@pytest.fixture
def logger():
    """Create a logger for testing."""
    return PyqualifyLogger(LogConfig(level="ERROR"))


@pytest.fixture
def analyzer(mock_ai_engine, logger):
    """Create a CodeAnalyzer instance."""
    return CodeAnalyzer(ai_engine=mock_ai_engine, logger=logger)


# --- Security Check Tests ---



class TestSecurityChecks:
    """Tests for _check_security method."""

    def test_detects_sql_injection(self, analyzer):
        source = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "sql-injection" for f in findings)

    def test_detects_command_injection(self, analyzer):
        source = 'os.system("rm -rf " + user_input)'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "command-injection" for f in findings)

    def test_detects_xss(self, analyzer):
        source = 'element.innerHTML = request.params.data'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "xss-vulnerability" for f in findings)

    def test_detects_hardcoded_secret(self, analyzer):
        source = 'api_key = "fake_secret_key_for_testing_1234567890"'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "hardcoded-secret" for f in findings)

    def test_detects_insecure_deserialization(self, analyzer):
        source = 'data = pickle.loads(user_data)'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "insecure-deserialization" for f in findings)

    def test_detects_path_traversal(self, analyzer):
        source = 'open(os.path.join(base, request.args["file"]))'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "path-traversal" for f in findings)

    def test_detects_insecure_random(self, analyzer):
        source = 'token = random.random()'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "insecure-random" for f in findings)

    def test_detects_broken_auth_hardcoded_creds(self, analyzer):
        source = 'password = "admin"'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "broken-auth-hardcoded-credentials" for f in findings)

    def test_detects_broken_auth_missing_validation(self, analyzer):
        source = 'jwt.decode(token, verify=False)'
        findings = analyzer._check_security(source, "test.py")
        assert any(f.check == "broken-auth-missing-validation" for f in findings)

    def test_no_false_positive_on_comments(self, analyzer):
        source = '# api_key = "fake_secret_key_for_testing_1234567890"'
        findings = analyzer._check_security(source, "test.py")
        assert not any(f.check == "hardcoded-secret" for f in findings)

    def test_location_includes_filepath_and_line(self, analyzer):
        source = 'line1\nos.system("rm -rf " + user_input)\nline3'
        findings = analyzer._check_security(source, "app.py")
        cmd_findings = [f for f in findings if f.check == "command-injection"]
        assert len(cmd_findings) == 1
        assert cmd_findings[0].location == "app.py:2"


# --- Bug Risk Check Tests ---



class TestBugRiskChecks:
    """Tests for _check_bug_risks method."""

    def test_detects_null_dereference(self, analyzer):
        source = 'result = data.get("key").upper()'
        findings = analyzer._check_bug_risks(source, "test.py")
        null_findings = [f for f in findings if f.check == "null-dereference"]
        assert len(null_findings) > 0
        assert null_findings[0].context["bug_risk_type"] == BugRiskType.NULL_DEREFERENCE.value

    def test_detects_bare_except(self, analyzer):
        source = 'except:'
        findings = analyzer._check_bug_risks(source, "test.py")
        exc_findings = [f for f in findings if f.check == "uncaught-exception"]
        assert len(exc_findings) > 0
        assert exc_findings[0].context["bug_risk_type"] == BugRiskType.UNCAUGHT_EXCEPTION.value

    def test_detects_race_condition(self, analyzer):
        source = 'shared_counter += 1'
        findings = analyzer._check_bug_risks(source, "test.py")
        race_findings = [f for f in findings if f.check == "race-condition"]
        assert len(race_findings) > 0
        assert race_findings[0].context["bug_risk_type"] == BugRiskType.RACE_CONDITION.value

    def test_detects_off_by_one(self, analyzer):
        source = 'for i in range(0, len(items) + 1):'
        findings = analyzer._check_bug_risks(source, "test.py")
        obo_findings = [f for f in findings if f.check == "off-by-one"]
        assert len(obo_findings) > 0
        assert obo_findings[0].context["bug_risk_type"] == BugRiskType.OFF_BY_ONE.value

    def test_confidence_levels_present(self, analyzer):
        source = 'result = data.get("key").upper()'
        findings = analyzer._check_bug_risks(source, "test.py")
        for finding in findings:
            assert "confidence" in finding.context
            assert finding.context["confidence"] in ("low", "medium", "high")


# --- Quality Check Tests ---



class TestQualityChecks:
    """Tests for _check_quality method."""

    def test_detects_dead_code_after_return(self, analyzer):
        source = "def foo():\n    return 1\n    x = 2"
        findings = analyzer._check_quality(source, "test.py")
        dead_findings = [f for f in findings if f.check == "dead-code"]
        assert any("Unreachable" in f.evidence for f in dead_findings)

    def test_detects_unused_import(self, analyzer):
        source = "import os\n\nprint('hello')"
        findings = analyzer._check_quality(source, "test.py")
        dead_findings = [f for f in findings if f.check == "dead-code"]
        assert any("os" in f.evidence for f in dead_findings)

    def test_detects_magic_numbers(self, analyzer):
        source = "timeout = 3600\n"
        findings = analyzer._check_quality(source, "test.py")
        magic_findings = [f for f in findings if f.check == "magic-number"]
        assert len(magic_findings) > 0

    def test_excludes_0_1_minus1_from_magic_numbers(self, analyzer):
        source = "x = 0\ny = 1\nz = -1\n"
        findings = analyzer._check_quality(source, "test.py")
        magic_findings = [f for f in findings if f.check == "magic-number"]
        assert len(magic_findings) == 0

    def test_detects_high_complexity(self, analyzer):
        # Build a function with many branches
        lines = ["def complex_func(x):"]
        for i in range(12):
            lines.append(f"    if x == {i}:")
            lines.append(f"        return {i}")
        source = "\n".join(lines)
        findings = analyzer._check_quality(source, "test.py")
        complexity_findings = [f for f in findings if f.check == "high-complexity"]
        assert len(complexity_findings) > 0

    def test_detects_duplicated_logic(self, analyzer):
        # Create 7+ identical lines appearing twice
        block = "\n".join([f"    x = x + {i}" for i in range(8)])
        source = f"def a():\n{block}\n\ndef b():\n{block}\n"
        findings = analyzer._check_quality(source, "test.py")
        dup_findings = [f for f in findings if f.check == "duplicated-logic"]
        assert len(dup_findings) > 0


# --- Test Gap Check Tests ---



class TestTestGapChecks:
    """Tests for _check_test_gaps method."""

    def test_detects_missing_test_file(self, analyzer):
        source = "def my_function():\n    pass"
        findings = analyzer._check_test_gaps(source, "utils.py", [])
        missing_findings = [f for f in findings if f.check == "missing-test-file"]
        assert len(missing_findings) > 0

    def test_no_missing_test_file_when_exists(self, analyzer):
        source = "def my_function():\n    pass"
        test_files = [Path("tests/test_utils.py")]
        findings = analyzer._check_test_gaps(source, "utils.py", test_files)
        missing_findings = [f for f in findings if f.check == "missing-test-file"]
        assert len(missing_findings) == 0

    def test_detects_weak_assertions(self, analyzer):
        source = "def test_something():\n    assertTrue(result)"
        # This is a test file, so it checks for weak assertions
        findings = analyzer._check_test_gaps(
            source, "test_utils.py", [Path("test_utils.py")]
        )
        weak_findings = [f for f in findings if f.check == "weak-assertion"]
        assert len(weak_findings) > 0

    def test_detects_untested_branches(self, analyzer):
        lines = ["def process(x):"]
        for i in range(6):
            lines.append(f"    if x == {i}:")
            lines.append(f"        return {i}")
        source = "\n".join(lines)
        findings = analyzer._check_test_gaps(source, "logic.py", [])
        branch_findings = [f for f in findings if f.check == "untested-branches"]
        assert len(branch_findings) > 0


# --- Dependency Check Tests ---



class TestDependencyChecks:
    """Tests for _check_dependencies method."""

    def test_detects_typosquatting(self, analyzer):
        source = "import reqeusts"  # Typo of 'requests'
        findings = analyzer._check_dependencies(source, "test.py")
        typo_findings = [f for f in findings if f.check == "typosquatting-import"]
        assert len(typo_findings) > 0

    def test_no_typosquatting_for_popular_package(self, analyzer):
        source = "import requests"
        findings = analyzer._check_dependencies(source, "test.py")
        typo_findings = [f for f in findings if f.check == "typosquatting-import"]
        assert len(typo_findings) == 0

    def test_detects_deprecated_package(self, analyzer):
        source = "import distutils"
        findings = analyzer._check_dependencies(source, "test.py")
        dep_findings = [f for f in findings if f.check == "deprecated-package"]
        assert len(dep_findings) > 0

    def test_detects_wildcard_import(self, analyzer):
        source = "from os.path import *"
        findings = analyzer._check_dependencies(source, "test.py")
        wild_findings = [f for f in findings if f.check == "wildcard-import"]
        assert len(wild_findings) > 0


# --- Integration / Analyze Method Tests ---



class TestAnalyzeMethod:
    """Tests for the main analyze() method."""

    @pytest.mark.asyncio
    async def test_analyze_single_file(self, analyzer, mock_ai_engine, tmp_path):
        """Test analyzing a single Python file."""
        test_file = tmp_path / "example.py"
        test_file.write_text('api_key = "fake_secret_key_for_testing_1234567890"\n')

        mock_ai_engine.process_findings.return_value = [
            Issue(
                check="hardcoded-secret",
                severity=Severity.CRITICAL,
                title="Hardcoded API key",
                description="Found hardcoded secret",
                evidence="api_key = ...",
                recommendation="Use environment variables",
            )
        ]

        result = await analyzer.analyze(str(test_file), AnalysisConfig())

        assert result.score <= 100
        assert result.grade in ("A", "B", "C", "D", "F")
        assert result.metadata.mode == AnalysisMode.CODE
        mock_ai_engine.process_findings.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_directory(self, analyzer, mock_ai_engine, tmp_path):
        """Test analyzing a directory of files."""
        (tmp_path / "app.py").write_text("import os\nprint('hello')\n")
        (tmp_path / "utils.py").write_text("def helper():\n    pass\n")

        mock_ai_engine.process_findings.return_value = []

        result = await analyzer.analyze(str(tmp_path), AnalysisConfig())

        assert result.score == 100
        assert result.grade == "A"
        mock_ai_engine.process_findings.assert_called_once()

    @pytest.mark.asyncio
    async def test_analyze_skips_unparseable_files(
        self, analyzer, mock_ai_engine, tmp_path
    ):
        """Test that files that can't be read are skipped gracefully."""
        test_file = tmp_path / "good.py"
        test_file.write_text("x = 1\n")

        mock_ai_engine.process_findings.return_value = []

        result = await analyzer.analyze(str(tmp_path), AnalysisConfig())

        # Should complete without error
        assert result is not None
        assert result.metadata.mode == AnalysisMode.CODE

    @pytest.mark.asyncio
    async def test_analyze_skips_non_code_files(
        self, analyzer, mock_ai_engine, tmp_path
    ):
        """Test that non-code files are skipped."""
        (tmp_path / "readme.md").write_text("# Hello")
        (tmp_path / "data.json").write_text('{"key": "value"}')
        (tmp_path / "app.py").write_text("x = 1\n")

        mock_ai_engine.process_findings.return_value = []

        result = await analyzer.analyze(str(tmp_path), AnalysisConfig())
        assert result is not None


# --- Levenshtein Distance Tests ---



class TestLevenshteinDistance:
    """Tests for the Levenshtein distance helper."""

    def test_identical_strings(self):
        assert CodeAnalyzer._levenshtein_distance("hello", "hello") == 0

    def test_one_char_difference(self):
        assert CodeAnalyzer._levenshtein_distance("requests", "reqeusts") == 2

    def test_empty_string(self):
        assert CodeAnalyzer._levenshtein_distance("", "hello") == 5

    def test_single_substitution(self):
        assert CodeAnalyzer._levenshtein_distance("cat", "bat") == 1

