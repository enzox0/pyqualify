"""HelpModal widget for the PyQualify TUI dashboard.

Displays a modal overlay listing all keyboard shortcuts grouped by
panel context with descriptions. Dismissed on Escape or ? key press,
returning focus to the previously focused panel.

Requirements: 6.5, 6.6
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from rich.text import Text

# Shortcut groups: (group_name, [(key, description), ...])
SHORTCUT_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Global",
        [
            ("q", "Quit"),
            ("?", "Help / Close"),
        ],
    ),
    (
        "Navigation",
        [
            ("1", "Focus Metrics"),
            ("2", "Focus Issues"),
            ("3", "Focus Logs"),
        ],
    ),
    (
        "Issues Panel",
        [
            ("Enter", "View Details"),
            ("s", "Sort"),
            ("Up/Down", "Navigate"),
            ("PgUp/PgDn", "Page"),
        ],
    ),
    (
        "Detail Panel",
        [
            ("Escape", "Close Detail"),
        ],
    ),
    (
        "Log Panel",
        [
            ("Up/Down", "Scroll"),
        ],
    ),
]


class HelpModal(ModalScreen):
    """Modal overlay listing all keyboard shortcuts grouped by context.

    Displays a centered container with shortcut groups using the
    dashboard's dark theme (panel-bg background, cyan border).
    Dismissed on Escape or ? key press.
    """

    BINDINGS = [
        Binding("escape", "dismiss", "Close", show=False),
        Binding("question_mark", "dismiss", "Close", show=False),
    ]

    def compose(self) -> ComposeResult:
        """Compose the help modal content with grouped shortcuts."""
        with VerticalScroll(id="help-container"):
            yield Static(self._build_title(), classes="help-title")
            for group_name, shortcuts in SHORTCUT_GROUPS:
                yield Static(
                    self._build_section_header(group_name),
                    classes="help-section",
                )
                yield Static(self._build_shortcut_list(shortcuts))

    def _build_title(self) -> Text:
        """Build the modal title text."""
        return Text("Keyboard Shortcuts", style="bold cyan")

    def _build_section_header(self, name: str) -> Text:
        """Build a section header for a shortcut group."""
        return Text(name, style="bold white")

    def _build_shortcut_list(self, shortcuts: list[tuple[str, str]]) -> Text:
        """Build a formatted list of key-description pairs.

        Keys are displayed in cyan, descriptions in muted color.
        """
        text = Text()
        for i, (key, description) in enumerate(shortcuts):
            if i > 0:
                text.append("\n")
            text.append("  ")
            text.append(f"{key:<12}", style="cyan")
            text.append(description, style="grey50")
        return text
