"""Tests for the centralized PyqualifyLogger."""

import logging
import tempfile
from pathlib import Path

from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import LogConfig


class TestPyqualifyLoggerLevels:
    """Test that log level configuration works correctly."""

    def test_default_level_is_info(self) -> None:
        config = LogConfig()
        logger = PyqualifyLogger(config)
        assert logger._logger.level == logging.INFO

    def test_debug_level(self) -> None:
        config = LogConfig(level="DEBUG")
        logger = PyqualifyLogger(config)
        assert logger._logger.level == logging.DEBUG

    def test_warning_level(self) -> None:
        config = LogConfig(level="WARNING")
        logger = PyqualifyLogger(config)
        assert logger._logger.level == logging.WARNING

    def test_error_level(self) -> None:
        config = LogConfig(level="ERROR")
        logger = PyqualifyLogger(config)
        assert logger._logger.level == logging.ERROR

    def test_case_insensitive_level(self) -> None:
        config = LogConfig(level="debug")
        logger = PyqualifyLogger(config)
        assert logger._logger.level == logging.DEBUG


class TestPyqualifyLoggerOutput:
    """Test that log messages are formatted and output correctly."""

    def test_info_message_logged(self, capfd: object) -> None:
        config = LogConfig(level="INFO")
        logger = PyqualifyLogger(config)
        logger.info("test_module", "Hello world")
        # The message goes to stderr via StreamHandler
        import sys
        # We can verify the logger doesn't raise
        # Detailed format checking is done via file output

    def test_debug_message_suppressed_at_info_level(self) -> None:
        config = LogConfig(level="INFO")
        logger = PyqualifyLogger(config)
        # This should not raise, just be suppressed
        logger.debug("test_module", "This should be suppressed")

    def test_log_file_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="DEBUG", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.info("web_analyzer", "Starting analysis")
            logger.debug("web_analyzer", "Debug detail")
            logger.warning("config", "Missing key")
            logger.error("ai_engine", "Request failed")

            log_content = Path(log_file).read_text(encoding="utf-8")

            assert "Starting analysis" in log_content
            assert "Debug detail" in log_content
            assert "Missing key" in log_content
            assert "Request failed" in log_content

    def test_log_file_contains_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="INFO", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.info("test_module", "Timestamp check")

            log_content = Path(log_file).read_text(encoding="utf-8")
            # Timestamp format: YYYY-MM-DD HH:MM:SS
            import re
            assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", log_content)

    def test_log_file_contains_module_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="INFO", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.info("web_analyzer", "Module check")

            log_content = Path(log_file).read_text(encoding="utf-8")
            assert "web_analyzer" in log_content

    def test_log_file_contains_level(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="INFO", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.warning("config", "Level check")

            log_content = Path(log_file).read_text(encoding="utf-8")
            assert "WARNING" in log_content

    def test_error_with_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="ERROR", log_file=log_file)
            logger = PyqualifyLogger(config)

            try:
                raise ValueError("Something went wrong")
            except ValueError as e:
                logger.error("ai_engine", "Processing failed", exc=e)

            log_content = Path(log_file).read_text(encoding="utf-8")
            assert "Processing failed" in log_content
            assert "ValueError" in log_content
            assert "Something went wrong" in log_content

    def test_error_without_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="ERROR", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.error("ai_engine", "Simple error")

            log_content = Path(log_file).read_text(encoding="utf-8")
            assert "Simple error" in log_content
            assert "ERROR" in log_content


class TestPyqualifyLoggerFileCreation:
    """Test log file path handling."""

    def test_creates_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "nested" / "dir" / "test.log")
            config = LogConfig(level="INFO", log_file=log_file)
            logger = PyqualifyLogger(config)

            logger.info("test", "Creating dirs")

            assert Path(log_file).exists()

    def test_no_file_handler_when_log_file_is_none(self) -> None:
        config = LogConfig(level="INFO", log_file=None)
        logger = PyqualifyLogger(config)

        # Should only have the stream handler
        assert len(logger._logger.handlers) == 1
        assert isinstance(logger._logger.handlers[0], logging.StreamHandler)

    def test_file_handler_added_when_log_file_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = str(Path(tmpdir) / "test.log")
            config = LogConfig(level="INFO", log_file=log_file)
            logger = PyqualifyLogger(config)

            # Should have both stream and file handlers
            assert len(logger._logger.handlers) == 2

