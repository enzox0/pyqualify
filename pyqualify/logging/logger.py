"""Centralized logging for PyQualify."""

import logging
import sys
from pathlib import Path

from pyqualify.models import LogConfig


class PyqualifyLogger:
    """Centralized logging with configurable levels and output.

    Wraps Python's built-in logging module to provide a consistent interface
    with timestamps and module identifiers in all log entries.
    """

    _LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
    _DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(self, config: LogConfig) -> None:
        self._logger = logging.getLogger("pyqualify")
        self._logger.setLevel(getattr(logging, config.level.upper(), logging.INFO))

        # Remove any existing handlers to avoid duplicates
        self._logger.handlers.clear()

        formatter = logging.Formatter(self._LOG_FORMAT, datefmt=self._DATE_FORMAT)

        # Always add a stream handler for console output
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        self._logger.addHandler(stream_handler)

        # Optionally add a file handler
        if config.log_file:
            log_path = Path(config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
            file_handler.setFormatter(formatter)
            self._logger.addHandler(file_handler)

    def debug(self, module: str, message: str) -> None:
        """Log a debug-level message."""
        self._get_module_logger(module).debug(message)

    def info(self, module: str, message: str) -> None:
        """Log an info-level message."""
        self._get_module_logger(module).info(message)

    def warning(self, module: str, message: str) -> None:
        """Log a warning-level message."""
        self._get_module_logger(module).warning(message)

    def error(self, module: str, message: str, exc: Exception | None = None) -> None:
        """Log an error-level message, optionally including exception info."""
        self._get_module_logger(module).error(message, exc_info=exc)

    def _get_module_logger(self, module: str) -> logging.Logger:
        """Get a child logger for the specified module."""
        child = self._logger.getChild(module)
        # Child loggers inherit handlers and level from parent
        return child
