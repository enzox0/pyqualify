"""Configuration manager with hierarchical precedence."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any


class ConfigManager:
    """Manages configuration with precedence: file < env < CLI.

    Configuration sources (lowest to highest priority):
    1. Configuration file (~/.pyqualify/config.toml)
    2. Environment variables (prefixed with PYQUALIFY_)
    3. CLI arguments (passed at runtime)
    """

    @property
    def CONFIG_DIR(self) -> Path:
        config_dir = os.environ.get("PYQUALIFY_CONFIG_DIR")
        if config_dir:
            return Path(config_dir)
        return Path.home() / ".pyqualify"

    @property
    def CONFIG_FILE(self) -> Path:
        return self.CONFIG_DIR / "config.toml"

    @property
    def ENV_FILE(self) -> Path:
        return self.CONFIG_DIR / "env"

    SENSITIVE_PATTERNS: list[str] = ["API_KEY", "SECRET", "TOKEN", "PASSWORD"]

    def __init__(self, cli_overrides: dict[str, Any] | None = None) -> None:
        """Initialize the config manager.

        Args:
            cli_overrides: Optional dict of CLI argument overrides (highest priority).
        """
        self._cli_overrides: dict[str, Any] = cli_overrides or {}
        self._ensure_config_dir()

    def get(self, key: str, default: Any = None) -> Any:
        """Get a config value respecting precedence: file < env < CLI.

        Args:
            key: The configuration key to look up.
            default: Default value if key is not found in any source.

        Returns:
            The configuration value from the highest-priority source, or default.
        """
        file_cfg = self._load_file_config()
        env_cfg = self._load_env_config()
        merged = self._merge_configs(file_cfg, env_cfg, self._cli_overrides)
        return merged.get(key, default)

    def set(self, key: str, value: str) -> None:
        """Set a value in the config file store.

        Args:
            key: The configuration key to set.
            value: The value to store.
        """
        self._ensure_config_dir()
        config = self._load_file_config()
        config[key] = value
        self._write_config(config)

    def delete(self, key: str) -> bool:
        """Delete a key from the config file store.

        Args:
            key: The configuration key to remove.

        Returns:
            True if the key existed and was removed, False otherwise.
        """
        config = self._load_file_config()
        if key not in config:
            return False
        del config[key]
        self._write_config(config)
        return True

    def list_all(self) -> dict[str, str]:
        """List all config entries with sensitive values masked.

        Returns:
            A dict of all configuration key-value pairs, with sensitive
            values masked to show only the first 4 characters.
        """
        file_cfg = self._load_file_config()
        env_cfg = self._load_env_config()
        merged = self._merge_configs(file_cfg, env_cfg, self._cli_overrides)

        result: dict[str, str] = {}
        for key, value in merged.items():
            str_value = str(value)
            if self.is_sensitive_key(key):
                result[key] = self.mask_value(str_value)
            else:
                result[key] = str_value
        return result

    def _load_file_config(self) -> dict[str, Any]:
        """Load configuration from the TOML config file.

        Returns:
            A flat dict of configuration values from the file,
            or an empty dict if the file doesn't exist or is invalid.
        """
        if not self.CONFIG_FILE.exists():
            return {}
        try:
            with open(self.CONFIG_FILE, "rb") as f:
                data = tomllib.load(f)
            return self._flatten_dict(data)
        except (tomllib.TOMLDecodeError, OSError):
            return {}

    def _load_env_config(self) -> dict[str, str]:
        """Load configuration from environment variables prefixed with PYQUALIFY_.

        Returns:
            A dict of config values derived from PYQUALIFY_-prefixed env vars.
            The PYQUALIFY_ prefix is stripped and the key is lowercased.
        """
        prefix = "PYQUALIFY_"
        env_cfg: dict[str, str] = {}
        for key, value in os.environ.items():
            if key.startswith(prefix):
                # Strip prefix and lowercase for consistent key naming
                config_key = key[len(prefix):].lower()
                env_cfg[config_key] = value
        return env_cfg

    def _merge_configs(
        self, file_cfg: dict[str, Any], env_cfg: dict[str, str], cli_cfg: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge configs with precedence: file < env < CLI.

        Args:
            file_cfg: Configuration from the TOML file (lowest priority).
            env_cfg: Configuration from environment variables.
            cli_cfg: Configuration from CLI arguments (highest priority).

        Returns:
            Merged configuration dict.
        """
        merged: dict[str, Any] = {}
        merged.update(file_cfg)
        merged.update(env_cfg)
        merged.update(cli_cfg)
        return merged

    def _ensure_config_dir(self) -> None:
        """Create config directory and file with owner-only permissions if not exists."""
        if not self.CONFIG_DIR.exists():
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            # Set owner-only permissions (0o700)
            try:
                self.CONFIG_DIR.chmod(0o700)
            except OSError:
                # On Windows, chmod may not work the same way; skip gracefully
                pass

        if not self.CONFIG_FILE.exists():
            self.CONFIG_FILE.touch()
            # Set owner-only read/write permissions (0o600)
            try:
                self.CONFIG_FILE.chmod(0o600)
            except OSError:
                pass

    def _write_config(self, config: dict[str, Any]) -> None:
        """Write configuration dict to the TOML config file.

        Uses manual TOML formatting since tomllib is read-only.

        Args:
            config: The configuration dict to persist.
        """
        self._ensure_config_dir()
        lines: list[str] = []
        for key, value in sorted(config.items()):
            lines.append(f"{key} = {self._format_toml_value(value)}")
        content = "\n".join(lines)
        if lines:
            content += "\n"
        self.CONFIG_FILE.write_text(content, encoding="utf-8")
        # Maintain owner-only permissions after write
        try:
            self.CONFIG_FILE.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _format_toml_value(value: Any) -> str:
        """Format a Python value as a TOML value string.

        Args:
            value: The value to format.

        Returns:
            A TOML-compatible string representation.
        """
        if isinstance(value, bool):
            return "true" if value else "false"
        elif isinstance(value, int):
            return str(value)
        elif isinstance(value, float):
            return str(value)
        elif isinstance(value, str):
            # Escape backslashes and quotes for TOML string
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        else:
            # Fallback: convert to string
            escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'

    @staticmethod
    def _flatten_dict(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
        """Flatten a nested dict into dot-separated keys.

        Args:
            data: The nested dict to flatten.
            prefix: Current key prefix for recursion.

        Returns:
            A flat dict with dot-separated keys.
        """
        result: dict[str, Any] = {}
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                result.update(ConfigManager._flatten_dict(value, full_key))
            else:
                result[full_key] = value
        return result

    def is_configured(self) -> bool:
        """Return True if the minimum required configuration is present.

        Requires at least: api_key and provider.
        """
        return bool(self.get("api_key")) and bool(self.get("provider"))

    @staticmethod
    def is_sensitive_key(key: str) -> bool:
        """Check if a key contains sensitive patterns.

        Args:
            key: The configuration key to check.

        Returns:
            True if the key matches any sensitive pattern.
        """
        sensitive_patterns = ["API_KEY", "SECRET", "TOKEN", "PASSWORD"]
        return any(p in key.upper() for p in sensitive_patterns)

    @staticmethod
    def mask_value(value: str) -> str:
        """Mask a sensitive value showing only first 4 chars.

        Args:
            value: The value to mask.

        Returns:
            Masked string with first 4 chars visible and rest as asterisks,
            or "****" if value is 4 chars or fewer.
        """
        if len(value) <= 4:
            return "****"
        return value[:4] + "*" * (len(value) - 4)
