"""Tests for the QAAI CLI main command group."""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from pyqualify.cli.main import cli
from pyqualify.models import (
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    Issue,
    RiskLevel,
    Severity,
)


def _make_result() -> AnalysisResult:
    """Create a sample AnalysisResult for testing."""
    return AnalysisResult(
        score=85,
        grade="B",
        risk_level=RiskLevel.MEDIUM,
        issues=[
            Issue(
                check="missing-csp",
                severity=Severity.MEDIUM,
                title="Missing CSP Header",
                description="No Content-Security-Policy header found.",
                evidence="Response headers lack CSP.",
                recommendation="Add a CSP header.",
            )
        ],
        summary="Found 1 issue.",
        metadata=AnalysisMetadata(
            timestamp="2024-01-01T00:00:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        ),
    )


class TestCLIGroup:
    """Tests for the top-level CLI group."""

    def test_help_shows_all_commands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "web" in result.output
        assert "code" in result.output
        assert "api" in result.output
        assert "config" in result.output

    def test_version_option(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower() or "0." in result.output


class TestWebCommand:
    """Tests for the web analysis command."""

    def test_invalid_url_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["web", "not-a-url"])
        assert result.exit_code == 1
        assert "Invalid value" in result.output or "\u2716" in result.output

    def test_missing_url_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["web"])
        assert result.exit_code != 0

    @patch("qaai.cli.main.ProgressIndicator")
    @patch("qaai.cli.main._build_container")
    @patch("qaai.cli.main.ConfigManager")
    def test_json_output_flag(self, mock_cm_class, mock_container_fn, mock_progress) -> None:
        mock_result = _make_result()

        mock_cm = MagicMock()
        mock_cm.get.return_value = "30"
        mock_cm_class.return_value = mock_cm

        mock_analyzer = MagicMock()
        mock_formatter = MagicMock()
        mock_html_gen = MagicMock()

        container_instance = MagicMock()

        def resolve_side_effect(cls):
            from pyqualify.analyzers.web_analyzer import WebAnalyzer as WA
            from pyqualify.reporting.cli_formatter import CLIFormatter as CF
            from pyqualify.reporting.html_generator import HTMLDashboardGenerator as HG

            if cls is WA:
                return mock_analyzer
            elif cls is CF:
                return mock_formatter
            elif cls is HG:
                return mock_html_gen
            return MagicMock()

        container_instance.resolve.side_effect = resolve_side_effect
        mock_container_fn.return_value = container_instance

        # Mock asyncio.run to return the result directly
        with patch("qaai.cli.main.asyncio.run", return_value=mock_result):
            runner = CliRunner()
            result = runner.invoke(cli, ["web", "https://example.com", "--json"])

        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["score"] == 85
        assert parsed["grade"] == "B"

    def test_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["web", "--help"])
        assert result.exit_code == 0
        assert "--only" in result.output
        assert "--json" in result.output


class TestCodeCommand:
    """Tests for the code analysis command."""

    def test_nonexistent_path_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["code", "/nonexistent/path/xyz"])
        assert result.exit_code == 1
        assert "Invalid value" in result.output or "\u2716" in result.output

    def test_missing_path_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["code"])
        assert result.exit_code != 0

    def test_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["code", "--help"])
        assert result.exit_code == 0
        assert "--only" in result.output
        assert "--json" in result.output


class TestAPICommand:
    """Tests for the api analysis command."""

    def test_invalid_url_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["api", "not-a-url"])
        assert result.exit_code == 1
        assert "Invalid value" in result.output or "\u2716" in result.output

    def test_missing_url_argument(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["api"])
        assert result.exit_code != 0

    def test_help_shows_options(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["api", "--help"])
        assert result.exit_code == 0
        assert "--only" in result.output
        assert "--json" in result.output


class TestConfigSubcommands:
    """Tests for the config subgroup commands."""

    def test_config_help_shows_subcommands(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["config", "--help"])
        assert result.exit_code == 0
        assert "set" in result.output
        assert "edit" in result.output
        assert "list" in result.output
        assert "delete" in result.output

    @patch("qaai.cli.main.ConfigManager")
    def test_config_set(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm_class.return_value = mock_cm
        mock_cm_class.is_sensitive_key.return_value = False

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set", "timeout", "60"])
        assert result.exit_code == 0
        assert "Set 'timeout' = '60'" in result.output
        mock_cm.set.assert_called_once_with("timeout", "60")

    @patch("qaai.cli.main.ConfigManager")
    def test_config_set_masks_sensitive_key(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm_class.return_value = mock_cm
        mock_cm_class.is_sensitive_key.return_value = True
        mock_cm_class.mask_value.return_value = "sk-1****"

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "set", "api_key", "sk-12345"])
        assert result.exit_code == 0
        assert "sk-1****" in result.output
        assert "sk-12345" not in result.output

    @patch("qaai.cli.main.ConfigManager")
    def test_config_list_empty(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm.list_all.return_value = {}
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "list"])
        assert result.exit_code == 0
        assert "No configuration values set." in result.output

    @patch("qaai.cli.main.ConfigManager")
    def test_config_list_with_entries(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm.list_all.return_value = {"timeout": "30", "model": "gpt-4o"}
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "list"])
        assert result.exit_code == 0
        assert "timeout = 30" in result.output
        assert "model = gpt-4o" in result.output

    @patch("qaai.cli.main.ConfigManager")
    def test_config_delete_existing_key(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm.delete.return_value = True
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "delete", "timeout"])
        assert result.exit_code == 0
        assert "Deleted 'timeout'." in result.output

    @patch("qaai.cli.main.ConfigManager")
    def test_config_delete_nonexistent_key(self, mock_cm_class) -> None:
        mock_cm = MagicMock()
        mock_cm.delete.return_value = False
        mock_cm_class.return_value = mock_cm

        runner = CliRunner()
        result = runner.invoke(cli, ["config", "delete", "nonexistent"])
        assert result.exit_code == 1


class TestDashboardCommand:
    """Tests for the dashboard command."""

    def test_help_shows_mode_and_target(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--help"])
        assert result.exit_code == 0
        assert "web" in result.output
        assert "code" in result.output
        assert "api" in result.output
        assert "TARGET" in result.output

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=True)
    @patch("pyqualify.cli.main._build_container")
    @patch("pyqualify.tui.app.DashboardApp")
    def test_no_arguments_launches_dashboard(self, mock_app_cls, mock_build, mock_configured) -> None:
        mock_app_instance = MagicMock()
        mock_app_cls.return_value = mock_app_instance
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard"])
        assert result.exit_code == 0
        mock_app_instance.run.assert_called_once()

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=True)
    @patch("pyqualify.cli.main._build_container")
    @patch("pyqualify.tui.app.DashboardApp")
    def test_valid_web_mode_with_url(self, mock_app_cls, mock_build, mock_configured) -> None:
        mock_app_instance = MagicMock()
        mock_app_cls.return_value = mock_app_instance
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "web", "https://example.com"])
        assert result.exit_code == 0
        mock_app_instance.run.assert_called_once()

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=True)
    @patch("pyqualify.cli.main._build_container")
    @patch("pyqualify.tui.app.DashboardApp")
    def test_valid_code_mode_with_existing_path(self, mock_app_cls, mock_build, mock_configured) -> None:
        mock_app_instance = MagicMock()
        mock_app_cls.return_value = mock_app_instance
        runner = CliRunner()
        # Use the test file itself as a valid path
        result = runner.invoke(cli, ["dashboard", "code", "pyproject.toml"])
        assert result.exit_code == 0
        mock_app_instance.run.assert_called_once()

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=True)
    @patch("pyqualify.cli.main._build_container")
    @patch("pyqualify.tui.app.DashboardApp")
    def test_valid_api_mode_with_url(self, mock_app_cls, mock_build, mock_configured) -> None:
        mock_app_instance = MagicMock()
        mock_app_cls.return_value = mock_app_instance
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "api", "https://api.example.com"])
        assert result.exit_code == 0
        mock_app_instance.run.assert_called_once()

    def test_invalid_mode_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "invalid"])
        assert result.exit_code != 0
        assert "is not one of" in result.output or "Invalid value" in result.output

    def test_web_mode_invalid_url_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "web", "not-a-url"])
        assert result.exit_code == 1
        assert "✖" in result.output

    def test_code_mode_nonexistent_path_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "code", "/nonexistent/path/xyz"])
        assert result.exit_code == 1
        assert "✖" in result.output

    def test_api_mode_invalid_url_returns_error(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "api", "ftp://invalid.com"])
        assert result.exit_code == 1
        assert "✖" in result.output

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=True)
    @patch("pyqualify.cli.main._build_container")
    @patch("pyqualify.tui.app.DashboardApp")
    def test_mode_only_without_target_launches_dashboard(self, mock_app_cls, mock_build, mock_configured) -> None:
        mock_app_instance = MagicMock()
        mock_app_cls.return_value = mock_app_instance
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "web"])
        assert result.exit_code == 0
        mock_app_instance.run.assert_called_once()

    @patch("pyqualify.cli.main.ConfigManager.is_configured", return_value=False)
    def test_not_configured_exits_with_setup_message(self, mock_configured) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard"])
        assert result.exit_code == 1
        assert "not configured" in result.output
        assert "pyqualify setup" in result.output


class TestErrorHandling:
    """Tests for comprehensive error handling."""

    def test_no_unhandled_exceptions_on_invalid_web_url(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["web", "ftp://invalid.com"])
        # Should not have a traceback in output
        assert "Traceback" not in result.output
        assert result.exit_code == 1

    def test_no_unhandled_exceptions_on_invalid_code_path(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["code", "/does/not/exist/at/all"])
        assert "Traceback" not in result.output
        assert result.exit_code == 1

    def test_no_unhandled_exceptions_on_invalid_api_url(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["api", "://broken"])
        assert "Traceback" not in result.output
        assert result.exit_code == 1

