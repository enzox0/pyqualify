"""Configuration management."""

from pyqualify.config.manager import ConfigManager

__all__ = ["ConfigEditor", "ConfigManager"]


def __getattr__(name: str):  # noqa: ANN204
    """Lazy import for ConfigEditor to avoid curses import on Windows."""
    if name == "ConfigEditor":
        from pyqualify.config.editor import ConfigEditor
        return ConfigEditor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
