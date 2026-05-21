"""Unit tests for the LogPanel widget.

Tests cover:
- Log entry appending and rendering
- 1000 entry maximum enforcement
- Auto-scroll behavior
- Manual scroll detection and new messages indicator
- Color-coding by log level
- Timestamp/level/message display format
"""

import pytest
from textual.app import App, ComposeResult

from pyqualify.tui.widgets.log_panel import LogPanel, LEVEL_COLORS, LEVEL_LABELS


class LogPanelApp(App[None]):
    """Test app that hosts a LogPanel widget."""

    def compose(self) -> ComposeResult:
        yield LogPanel(id="log-panel")


@pytest.fixture
def log_panel_app():
    """Create a test app with a LogPanel."""
    return LogPanelApp()


class TestLogPanelAppend:
    """Tests for append_log functionality."""

    async def test_append_single_entry(self, log_panel_app: LogPanelApp):
        """Test appending a single log entry."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            panel.append_log("12:30:45", "info", "Test message")

            assert len(panel._entries) == 1
            assert panel._entries[0].timestamp == "12:30:45"
            assert panel._entries[0].level == "info"
            assert panel._entries[0].message == "Test message"

    async def test_append_multiple_entries(self, log_panel_app: LogPanelApp):
        """Test appending multiple log entries preserves order."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            panel.append_log("12:00:00", "info", "First")
            panel.append_log("12:00:01", "warning", "Second")
            panel.append_log("12:00:02", "error", "Third")

            assert len(panel._entries) == 3
            assert panel._entries[0].message == "First"
            assert panel._entries[1].message == "Second"
            assert panel._entries[2].message == "Third"

    async def test_append_all_log_levels(self, log_panel_app: LogPanelApp):
        """Test that all log levels are accepted."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            for level in ("debug", "info", "warning", "error"):
                panel.append_log("10:00:00", level, f"{level} message")

            assert len(panel._entries) == 4


class TestLogPanelMaxEntries:
    """Tests for the 1000 entry maximum enforcement (Req 5.7)."""

    async def test_max_entries_limit(self, log_panel_app: LogPanelApp):
        """Test that entries are capped at MAX_ENTRIES (1000)."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)

            # Add more than MAX_ENTRIES
            for i in range(1050):
                panel.append_log(f"10:{i // 60:02d}:{i % 60:02d}", "info", f"Message {i}")

            assert len(panel._entries) == 1000

    async def test_oldest_entries_discarded(self, log_panel_app: LogPanelApp):
        """Test that the oldest entries are discarded when limit exceeded."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)

            for i in range(1010):
                panel.append_log("10:00:00", "info", f"Message {i}")

            # The first 10 messages should have been discarded
            assert panel._entries[0].message == "Message 10"
            assert panel._entries[-1].message == "Message 1009"

    async def test_max_entries_constant(self):
        """Test that MAX_ENTRIES is set to 1000."""
        assert LogPanel.MAX_ENTRIES == 1000


class TestLogPanelAutoScroll:
    """Tests for auto-scroll behavior (Req 5.2, 5.3, 5.4)."""

    async def test_auto_scroll_enabled_by_default(self, log_panel_app: LogPanelApp):
        """Test that auto-scroll is enabled when panel is first created."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            assert panel._auto_scroll is True

    async def test_unseen_count_starts_at_zero(self, log_panel_app: LogPanelApp):
        """Test that unseen count starts at zero."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            assert panel._unseen_count == 0

    async def test_no_unseen_when_auto_scroll_active(self, log_panel_app: LogPanelApp):
        """Test that unseen count stays 0 when auto-scroll is active."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            panel.append_log("10:00:00", "info", "Message 1")
            panel.append_log("10:00:01", "info", "Message 2")

            assert panel._unseen_count == 0

    async def test_unseen_increments_when_auto_scroll_paused(
        self, log_panel_app: LogPanelApp
    ):
        """Test that unseen count increments when auto-scroll is paused."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            panel._auto_scroll = False

            panel.append_log("10:00:00", "info", "Message 1")
            panel.append_log("10:00:01", "info", "Message 2")

            assert panel._unseen_count == 2

    async def test_unseen_resets_when_auto_scroll_resumes(
        self, log_panel_app: LogPanelApp
    ):
        """Test that unseen count resets to 0 when auto-scroll resumes."""
        async with log_panel_app.run_test() as pilot:
            panel = log_panel_app.query_one("#log-panel", LogPanel)
            panel._auto_scroll = False
            panel.append_log("10:00:00", "info", "Message 1")
            panel.append_log("10:00:01", "info", "Message 2")

            # Resume auto-scroll
            panel._auto_scroll = True

            assert panel._unseen_count == 0


class TestLogPanelColorCoding:
    """Tests for log level color coding (Req 5.6)."""

    def test_level_colors_defined(self):
        """Test that all required level colors are defined."""
        assert "debug" in LEVEL_COLORS
        assert "info" in LEVEL_COLORS
        assert "warning" in LEVEL_COLORS
        assert "error" in LEVEL_COLORS

    def test_debug_color_is_gray(self):
        """Test debug entries use gray color."""
        assert "grey" in LEVEL_COLORS["debug"]

    def test_info_color_is_white(self):
        """Test info entries use white color."""
        assert LEVEL_COLORS["info"] == "white"

    def test_warning_color_is_yellow(self):
        """Test warning entries use yellow color."""
        assert LEVEL_COLORS["warning"] == "yellow"

    def test_error_color_is_red(self):
        """Test error entries use red color."""
        assert LEVEL_COLORS["error"] == "red"


class TestLogPanelLevelLabels:
    """Tests for level label formatting (Req 5.5)."""

    def test_level_labels_defined(self):
        """Test that all level labels are defined."""
        assert "debug" in LEVEL_LABELS
        assert "info" in LEVEL_LABELS
        assert "warning" in LEVEL_LABELS
        assert "error" in LEVEL_LABELS

    def test_labels_are_fixed_width(self):
        """Test that all labels are the same width for alignment."""
        widths = {len(label) for label in LEVEL_LABELS.values()}
        assert len(widths) == 1, "All level labels should be the same width"
