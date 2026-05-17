"""Tests for the __main__.py entry point."""

import subprocess
import sys
from unittest.mock import patch

from pyqualify.__main__ import main


class TestMainEntryPoint:
    """Tests for the __main__.py module."""

    def test_main_function_invokes_cli(self) -> None:
        """Verify main() calls the cli function."""
        with patch("pyqualify.__main__.cli") as mock_cli:
            mock_cli.side_effect = SystemExit(0)
            try:
                main()
            except SystemExit:
                pass
            mock_cli.assert_called_once()

    def test_python_m_qaai_help(self) -> None:
        """Verify `python -m pyqualify --help` works end-to-end."""
        result = subprocess.run(
            [sys.executable, "-m", "pyqualify", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "pyqualify" in result.stdout
        assert "web" in result.stdout
        assert "code" in result.stdout
        assert "api" in result.stdout
        assert "config" in result.stdout

    def test_python_m_qaai_version(self) -> None:
        """Verify `python -m pyqualify --version` outputs version info."""
        result = subprocess.run(
            [sys.executable, "-m", "pyqualify", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "0.1.0" in result.stdout

