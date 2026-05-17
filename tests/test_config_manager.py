"""Tests for the ConfigManager class."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pyqualify.config.manager import ConfigManager


@pytest.fixture
def tmp_config_dir(tmp_path: Path) -> Path:
    """Create a temporary config directory for testing."""
    config_dir = tmp_path / ".qaai"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def config_manager(tmp_path: Path) -> ConfigManager:
    """Create a ConfigManager with a temporary config directory."""
    config_dir = tmp_path / ".qaai"
    config_file = config_dir / "config.toml"
    with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
        with patch.object(ConfigManager, "CONFIG_FILE", config_file):
            manager = ConfigManager()
    return manager


@pytest.fixture
def patched_manager(tmp_path: Path):
    """Context manager that patches ConfigManager paths for the duration of use."""
    config_dir = tmp_path / ".qaai"
    config_file = config_dir / "config.toml"

    with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
        with patch.object(ConfigManager, "CONFIG_FILE", config_file):
            yield ConfigManager()


class TestConfigManagerInit:
    """Tests for ConfigManager initialization."""

    def test_creates_config_dir_if_not_exists(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_file = config_dir / "config.toml"
        assert not config_dir.exists()

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                ConfigManager()

        assert config_dir.exists()

    def test_creates_config_file_if_not_exists(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_file = config_dir / "config.toml"

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                ConfigManager()

        assert config_file.exists()

    def test_does_not_fail_if_dir_already_exists(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()

        assert config_dir.exists()


class TestConfigGet:
    """Tests for ConfigManager.get()."""

    def test_get_returns_default_when_key_not_found(self, patched_manager: ConfigManager) -> None:
        assert patched_manager.get("nonexistent") is None
        assert patched_manager.get("nonexistent", "fallback") == "fallback"

    def test_get_reads_from_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\ntimeout = 30\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                assert manager.get("model") == "gpt-4o"
                assert manager.get("timeout") == 30

    def test_get_env_overrides_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                with patch.dict(os.environ, {"PYQUALIFY_MODEL": "gpt-3.5-turbo"}):
                    manager = ConfigManager()
                    assert manager.get("model") == "gpt-3.5-turbo"

    def test_get_cli_overrides_env(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                with patch.dict(os.environ, {"PYQUALIFY_MODEL": "gpt-3.5-turbo"}):
                    manager = ConfigManager(cli_overrides={"model": "claude-3"})
                    assert manager.get("model") == "claude-3"

    def test_get_precedence_order(self, tmp_path: Path) -> None:
        """Test full precedence: file < env < CLI."""
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text(
            'file_only = "from_file"\nenv_override = "from_file"\ncli_override = "from_file"\n',
            encoding="utf-8",
        )

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                with patch.dict(
                    os.environ,
                    {"PYQUALIFY_ENV_OVERRIDE": "from_env", "PYQUALIFY_CLI_OVERRIDE": "from_env"},
                ):
                    manager = ConfigManager(cli_overrides={"cli_override": "from_cli"})
                    assert manager.get("file_only") == "from_file"
                    assert manager.get("env_override") == "from_env"
                    assert manager.get("cli_override") == "from_cli"


class TestConfigSet:
    """Tests for ConfigManager.set()."""

    def test_set_creates_new_key(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("", encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                manager.set("api_key", "sk-12345")
                assert manager.get("api_key") == "sk-12345"

    def test_set_updates_existing_key(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                manager.set("model", "gpt-3.5-turbo")
                assert manager.get("model") == "gpt-3.5-turbo"

    def test_set_persists_to_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("", encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                manager.set("base_url", "https://api.example.com")

                # Read file directly to verify persistence
                content = config_file.read_text(encoding="utf-8")
                assert "base_url" in content
                assert "https://api.example.com" in content


class TestConfigDelete:
    """Tests for ConfigManager.delete()."""

    def test_delete_existing_key_returns_true(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                assert manager.delete("model") is True
                assert manager.get("model") is None

    def test_delete_nonexistent_key_returns_false(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("", encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                assert manager.delete("nonexistent") is False

    def test_delete_removes_from_file(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\ntimeout = 30\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                manager.delete("model")
                content = config_file.read_text(encoding="utf-8")
                assert "model" not in content
                assert "timeout" in content


class TestConfigListAll:
    """Tests for ConfigManager.list_all()."""

    def test_list_all_returns_all_merged_config(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\ntimeout = 30\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                result = manager.list_all()
                assert "model" in result
                assert "timeout" in result

    def test_list_all_masks_sensitive_values(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('api_key = "sk-1234567890"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                result = manager.list_all()
                assert result["api_key"] == "sk-1**********"

    def test_list_all_does_not_mask_non_sensitive(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text('model = "gpt-4o"\n', encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                result = manager.list_all()
                assert result["model"] == "gpt-4o"


class TestSensitiveKeyDetection:
    """Tests for ConfigManager.is_sensitive_key()."""

    def test_detects_api_key(self) -> None:
        assert ConfigManager.is_sensitive_key("api_key") is True
        assert ConfigManager.is_sensitive_key("OPENAI_API_KEY") is True

    def test_detects_secret(self) -> None:
        assert ConfigManager.is_sensitive_key("client_secret") is True
        assert ConfigManager.is_sensitive_key("SECRET_VALUE") is True

    def test_detects_token(self) -> None:
        assert ConfigManager.is_sensitive_key("auth_token") is True
        assert ConfigManager.is_sensitive_key("ACCESS_TOKEN") is True

    def test_detects_password(self) -> None:
        assert ConfigManager.is_sensitive_key("db_password") is True
        assert ConfigManager.is_sensitive_key("PASSWORD") is True

    def test_non_sensitive_keys(self) -> None:
        assert ConfigManager.is_sensitive_key("model") is False
        assert ConfigManager.is_sensitive_key("timeout") is False
        assert ConfigManager.is_sensitive_key("base_url") is False
        assert ConfigManager.is_sensitive_key("log_level") is False


class TestMaskValue:
    """Tests for ConfigManager.mask_value()."""

    def test_mask_short_value(self) -> None:
        assert ConfigManager.mask_value("abc") == "****"
        assert ConfigManager.mask_value("abcd") == "****"
        assert ConfigManager.mask_value("") == "****"

    def test_mask_longer_value(self) -> None:
        assert ConfigManager.mask_value("sk-12345") == "sk-1****"
        assert ConfigManager.mask_value("abcde") == "abcd*"
        assert ConfigManager.mask_value("hello_world") == "hell*******"

    def test_mask_preserves_first_four_chars(self) -> None:
        value = "mysecretvalue123"
        masked = ConfigManager.mask_value(value)
        assert masked[:4] == "myse"
        assert masked[4:] == "*" * (len(value) - 4)


class TestEnvConfig:
    """Tests for environment variable loading."""

    def test_loads_qaai_prefixed_env_vars(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("", encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                with patch.dict(os.environ, {"PYQUALIFY_MODEL": "gpt-4", "PYQUALIFY_TIMEOUT": "60"}):
                    manager = ConfigManager()
                    assert manager.get("model") == "gpt-4"
                    assert manager.get("timeout") == "60"

    def test_ignores_non_qaai_env_vars(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text("", encoding="utf-8")

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                with patch.dict(os.environ, {"OTHER_VAR": "value"}, clear=False):
                    manager = ConfigManager()
                    assert manager.get("other_var") is None


class TestNestedTomlConfig:
    """Tests for nested TOML configuration handling."""

    def test_flattens_nested_config(self, tmp_path: Path) -> None:
        config_dir = tmp_path / ".qaai"
        config_dir.mkdir()
        config_file = config_dir / "config.toml"
        config_file.write_text(
            '[ai]\nmodel = "gpt-4o"\ntimeout = 60\n',
            encoding="utf-8",
        )

        with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
            with patch.object(ConfigManager, "CONFIG_FILE", config_file):
                manager = ConfigManager()
                assert manager.get("ai.model") == "gpt-4o"
                assert manager.get("ai.timeout") == 60

