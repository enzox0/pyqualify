"""LogPanel widget for the PyQualify TUI dashboard.

Displays a live-scrolling log feed with auto-scroll behavior,
manual scroll detection, color-coded log levels, and a "new messages"
indicator when the user scrolls up.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7
"""

from __future__ import annotations

from collections import deque

from rich.text import Text
from textual.containers import VerticalScroll
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from pyqualify.tui.models import LogEntry

# Color mapping for log levels (Req 5.6)
LEVEL_COLORS: dict[str, str] = {
    "debug": "grey50",
    "info": "white",
    "warning": "yellow",
    "error": "red",
}

# Level label display widths for alignment
LEVEL_LABELS: dict[str, str] = {
    "debug": "DEBUG",
    "info": "INFO ",
    "warning": "WARN ",
    "error": "ERROR",
}


class _LogLine(Static):
    """A single rendered log entry line."""

    def __init__(self, entry: LogEntry) -> None:
        super().__init__()
        self._entry = entry

    def render(self) -> Text:
        """Render the log entry with color-coded level."""
        entry = self._entry
        color = LEVEL_COLORS.get(entry.level, "white")
        label = LEVEL_LABELS.get(entry.level, entry.level.upper().ljust(5))

        text = Text()
        text.append(f"{entry.timestamp} ", style="grey70")
        text.append(f"{label} ", style=f"bold {color}")
        text.append(entry.message, style=color)
        return text


class LogPanel(Widget):
    """Live-scrolling log feed with auto-scroll and manual scroll detection.

    Displays timestamped, color-coded log entries and manages auto-scroll
    behavior. When the user scrolls up, auto-scroll pauses and a "new messages"
    indicator appears. Scrolling back to the bottom resumes auto-scroll.

    Enforces a maximum of 1000 entries, discarding the oldest when exceeded.
    """

    MAX_ENTRIES: int = 1000

    DEFAULT_CSS = """
    LogPanel {
        height: 100%;
        width: 100%;
    }

    LogPanel #log-scroll {
        height: 1fr;
        width: 100%;
    }

    LogPanel #new-messages-indicator {
        dock: bottom;
        height: 1;
        width: 100%;
        background: #1a1a1a;
        color: cyan;
        text-align: center;
        text-style: bold;
        display: none;
    }

    LogPanel #new-messages-indicator.visible {
        display: block;
    }
    """

    # Reactive property tracking unseen message count
    _unseen_count: reactive[int] = reactive(0)
    _auto_scroll: reactive[bool] = reactive(True)

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._entries: deque[LogEntry] = deque(maxlen=self.MAX_ENTRIES)
        self._line_widgets: deque[_LogLine] = deque(maxlen=self.MAX_ENTRIES)

    def compose(self):
        """Compose the log panel with a scrollable container and indicator."""
        yield VerticalScroll(id="log-scroll")
        yield Static("", id="new-messages-indicator")

    def append_log(self, timestamp: str, level: str, message: str) -> None:
        """Append a new log entry to the panel.

        Args:
            timestamp: Time string in HH:MM:SS format.
            level: Log level - "debug", "info", "warning", or "error".
            message: The log message text.
        """
        entry = LogEntry(timestamp=timestamp, level=level, message=message)
        self._entries.append(entry)

        # If we've exceeded max entries, remove the oldest widget
        scroll = self.query_one("#log-scroll", VerticalScroll)
        if len(self._line_widgets) >= self.MAX_ENTRIES:
            oldest_widget = self._line_widgets.popleft()
            oldest_widget.remove()

        # Create and mount the new log line widget
        line_widget = _LogLine(entry)
        self._line_widgets.append(line_widget)
        scroll.mount(line_widget)

        if self._auto_scroll:
            scroll.scroll_end(animate=False)
        else:
            self._unseen_count += 1

    def on_mount(self) -> None:
        """Set up scroll monitoring after mount."""
        scroll = self.query_one("#log-scroll", VerticalScroll)
        scroll.can_focus = True

    def watch__unseen_count(self, count: int) -> None:
        """Update the new messages indicator when unseen count changes."""
        indicator = self.query_one("#new-messages-indicator", Static)
        if count > 0:
            indicator.update(f"↓ {count} new message{'s' if count != 1 else ''}")
            indicator.add_class("visible")
        else:
            indicator.update("")
            indicator.remove_class("visible")

    def watch__auto_scroll(self, auto_scroll: bool) -> None:
        """Handle auto-scroll state changes."""
        if auto_scroll:
            self._unseen_count = 0

    def on_vertical_scroll_scroll_up(self) -> None:
        """Detect when user scrolls up manually - pause auto-scroll."""
        self._auto_scroll = False

    def on_vertical_scroll_scroll_down(self) -> None:
        """Detect when user scrolls down - check if at bottom."""
        self._check_at_bottom()

    def _check_at_bottom(self) -> None:
        """Check if the scroll container is at the bottom and resume auto-scroll."""
        scroll = self.query_one("#log-scroll", VerticalScroll)
        # Consider "at bottom" if within a small threshold of max scroll
        if scroll.scroll_y >= scroll.max_scroll_y - 1:
            self._auto_scroll = True

    def _on_scroll(self) -> None:
        """Handle generic scroll events for auto-scroll detection."""
        scroll = self.query_one("#log-scroll", VerticalScroll)
        if scroll.scroll_y >= scroll.max_scroll_y - 1:
            self._auto_scroll = True
        elif scroll.max_scroll_y > 0:
            self._auto_scroll = False
