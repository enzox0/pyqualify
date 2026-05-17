"""Tests for the ConfigEditor validation and persistence logic."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyqualify.config.editor import ConfigEditor
from pyqualify.config.manager import ConfigManager


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary config directory."""
    config_dir = tmp_path / ".qaai"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def config_manager(tmp_config_dir: Path) -> ConfigManager:
    """Create a ConfigManager with a temporary config directory."""
    manager = ConfigManager()
    # Override paths to use temp directory
    manager.CONFIG_DIR = tmp_config_dir
    manager.CONFIG_FILE = tmp_config_dir / "config.toml"
    manager.ENV_FILE = tmp_config_dir / "env"
    manager.CONFIG_FILE.touch()
    return manager


@pytest.fixture
def editor(config_manager: ConfigManager) -> ConfigEditor:
    """Create a ConfigEditor instance for testing."""
    return ConfigEditor(config_manager)


class TestValidateEntries:
    """Tests for _validate_entries method."""

    def test_valid_key_value_entries(self, editor: ConfigEditor) -> None:
        """Valid KEY=VALUE lines should produce no errors."""
        lines = ["API_KEY=sk-12345", "MODEL=gpt-4o", "TIMEOUT=60"]
        errors = editor._validate_entries(lines)
        assert errors == []

    def test_missing_equals_separator(self, editor: ConfigEditor) -> None:
        """Lines without '=' should produce an error."""
        lines = ["API_KEY=sk-12345", "INVALID_LINE", "MODEL=gpt-4o"]
        errors = editor._validate_entries(lines)
        assert len(errors) == 1
        assert errors[0][0] == 2  # Line number (1-based)
        assert "Missing '=' separator" in errors[0][1]

    def test_empty_key(self, editor: ConfigEditor) -> None:
        """Lines with empty key portion should produce an error."""
        lines = ["=some_value"]
        errors = editor._validate_entries(lines)
        assert len(errors) == 1
        assert errors[0][0] == 1
        assert "Empty key" in errors[0][1]

    def test_empty_lines_are_skipped(self, editor: ConfigEditor) -> None:
        """Empty lines should be skipped without error."""
        lines = ["API_KEY=value", "", "  ", "MODEL=gpt-4o"]
        errors = editor._validate_entries(lines)
        assert errors == []

    def test_comment_lines_are_skipped(self, editor: ConfigEditor) -> None:
        """Lines starting with # should be skipped."""
        lines = ["# This is a comment", "API_KEY=value"]
        errors = editor._validate_entries(lines)
        assert errors == []

    def test_value_can_be_empty(self, editor: ConfigEditor) -> None:
        """KEY= with empty value should be valid."""
        lines = ["EMPTY_VALUE="]
        errors = editor._validate_entries(lines)
        assert errors == []

    def test_value_can_contain_equals(self, editor: ConfigEditor) -> None:
        """Values containing '=' should be valid (only first = is separator)."""
        lines = ["BASE_URL=https://api.example.com?key=abc"]
        errors = editor._validate_entries(lines)
        assert errors == []

    def test_multiple_errors(self, editor: ConfigEditor) -> None:
        """Multiple invalid lines should each produce an error."""
        lines = ["VALID=ok", "no_equals", "=empty_key", "ALSO_VALID=yes"]
        errors = editor._validate_entries(lines)
        assert len(errors) == 2
        assert errors[0] == (2, "Missing '=' separator")
        assert errors[1] == (3, "Empty key")

    def test_whitespace_around_key(self, editor: ConfigEditor) -> None:
        """Keys with leading/trailing whitespace should still be valid if non-empty."""
        lines = ["  KEY  =value"]
        errors = editor._validate_entries(lines)
        assert errors == []


class TestSave:
    """Tests for _save method (validation + persistence)."""

    def test_save_valid_entries(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """Valid entries should be saved without errors."""
        editor._lines = ["API_KEY=sk-test123", "MODEL=gpt-4o"]
        errors = editor._save()
        assert errors == []

        # Verify env file was written
        env_content = config_manager.ENV_FILE.read_text(encoding="utf-8")
        assert "API_KEY=sk-test123" in env_content
        assert "MODEL=gpt-4o" in env_content

    def test_save_with_invalid_entries_returns_errors(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """Invalid entries should return error messages and not persist."""
        editor._lines = ["VALID=ok", "invalid_line"]
        errors = editor._save()
        assert len(errors) == 1
        assert "Line 2" in errors[0]
        assert "Missing '=' separator" in errors[0]

    def test_save_persists_to_config_manager(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """Saved entries should be accessible via the config manager."""
        editor._lines = ["TIMEOUT=30"]
        errors = editor._save()
        assert errors == []

        # The value should be in the config manager's store
        value = config_manager.get("TIMEOUT")
        assert value is not None


class TestLoadConfig:
    """Tests for _load_config method."""

    def test_load_from_env_file(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """Should load lines from the env file if it exists."""
        config_manager.ENV_FILE.write_text(
            "API_KEY=test\nMODEL=gpt-4\n", encoding="utf-8"
        )
        editor._load_config()
        assert editor._lines == ["API_KEY=test", "MODEL=gpt-4"]

    def test_load_empty_creates_one_line(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """If no config exists, should have at least one empty line."""
        # Ensure env file doesn't exist
        if config_manager.ENV_FILE.exists():
            config_manager.ENV_FILE.unlink()
        # Ensure config file is empty
        config_manager.CONFIG_FILE.write_text("", encoding="utf-8")

        editor._load_config()
        assert editor._lines == [""]

    def test_load_from_config_file_when_no_env(
        self, editor: ConfigEditor, config_manager: ConfigManager
    ) -> None:
        """Should fall back to config file entries when env file doesn't exist."""
        if config_manager.ENV_FILE.exists():
            config_manager.ENV_FILE.unlink()
        config_manager.CONFIG_FILE.write_text(
            'api_key = "sk-abc"\nmodel = "gpt-4o"\n', encoding="utf-8"
        )

        editor._load_config()
        # Should have key=value format lines from the TOML config
        assert any("api_key=" in line for line in editor._lines)
        assert any("model=" in line for line in editor._lines)


class TestHandleInput:
    """Tests for _handle_input key handling logic."""

    def test_ctrl_x_exits(self, editor: ConfigEditor) -> None:
        """Ctrl+X (ASCII 24) should set running to False."""
        editor._lines = ["test=value"]
        editor._running = True
        result = editor._handle_input(24)
        assert result is False
        assert editor._running is False

    def test_ctrl_k_deletes_line(self, editor: ConfigEditor) -> None:
        """Ctrl+K (ASCII 11) should delete the current line."""
        editor._lines = ["line1=a", "line2=b", "line3=c"]
        editor._cursor_row = 1
        editor._cursor_col = 0
        editor._handle_input(11)
        assert editor._lines == ["line1=a", "line3=c"]

    def test_ctrl_k_clears_last_line(self, editor: ConfigEditor) -> None:
        """Ctrl+K on the only line should clear it."""
        editor._lines = ["only_line=value"]
        editor._cursor_row = 0
        editor._cursor_col = 5
        editor._handle_input(11)
        assert editor._lines == [""]
        assert editor._cursor_col == 0

    def test_regular_character_input(self, editor: ConfigEditor) -> None:
        """Regular characters should be inserted at cursor position."""
        editor._lines = ["KEY="]
        editor._cursor_row = 0
        editor._cursor_col = 4
        editor._handle_input(ord("v"))
        assert editor._lines == ["KEY=v"]
        assert editor._cursor_col == 5

    def test_backspace_deletes_character(self, editor: ConfigEditor) -> None:
        """Backspace should delete the character before cursor."""
        editor._lines = ["KEY=value"]
        editor._cursor_row = 0
        editor._cursor_col = 5
        editor._handle_input(127)  # Backspace
        assert editor._lines == ["KEY=alue"]
        assert editor._cursor_col == 4

    def test_enter_splits_line(self, editor: ConfigEditor) -> None:
        """Enter should split the current line at cursor position."""
        editor._lines = ["KEY=value"]
        editor._cursor_row = 0
        editor._cursor_col = 4
        editor._handle_input(10)  # Enter
        assert editor._lines == ["KEY=", "value"]
        assert editor._cursor_row == 1
        assert editor._cursor_col == 0

