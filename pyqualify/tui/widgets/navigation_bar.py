"""NavigationBar widget for the PyQualify TUI dashboard.

Displays context-sensitive keyboard shortcuts as labeled key-action pairs
in a footer region. Updates dynamically based on the currently focused panel,
always showing global shortcuts (quit, help) alongside panel-specific ones.

Requirements: 6.1, 6.4
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

# Maximum number of shortcuts to display simultaneously (Req 6.1)
MAX_SHORTCUTS: int = 10

# Global shortcuts always shown regardless of context (Req 6.4)
GLOBAL_SHORTCUTS: list[tuple[str, str]] = [
    ("q", "Quit"),
    ("?", "Help"),
]

# Panel focus shortcuts shown in all contexts
PANEL_SHORTCUTS: list[tuple[str, str]] = [
    ("1", "Metrics"),
    ("2", "Issues"),
    ("3", "Logs"),
]

# Context-specific shortcuts per focused panel (Req 6.4)
CONTEXT_SHORTCUTS: dict[str, list[tuple[str, str]]] = {
    "metrics": [],
    "issues": [
        ("Enter", "Details"),
        ("s", "Sort"),
    ],
    "logs": [],
}


class NavigationBar(Static):
    """Footer displaying context-sensitive keyboard shortcuts.

    Shows key-action pairs using Rich markup with cyan for key labels
    and muted color for action text. Displays a maximum of 10 shortcuts
    at any time, combining global shortcuts with context-specific ones
    based on the currently focused panel.
    """

    DEFAULT_CSS = """
    NavigationBar {
        height: auto;
        width: 100%;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._focused_panel: str = ""

    def on_mount(self) -> None:
        """Render the navigation bar with default shortcuts on mount."""
        self._render_shortcuts()

    def update_context(self, focused_panel: str) -> None:
        """Update displayed shortcuts based on the currently focused panel.

        Shows context-sensitive shortcuts for the focused panel combined
        with global shortcuts (quit, help) and panel focus shortcuts.

        Args:
            focused_panel: Identifier of the focused panel -
                "metrics", "issues", or "logs".
        """
        self._focused_panel = focused_panel
        self._render_shortcuts()

    def _get_shortcuts(self) -> list[tuple[str, str]]:
        """Build the list of shortcuts to display for the current context.

        Combines context-specific shortcuts with panel focus shortcuts
        and global shortcuts, capped at MAX_SHORTCUTS.

        Returns:
            A list of (key, action) tuples to display.
        """
        shortcuts: list[tuple[str, str]] = []

        # Add context-specific shortcuts first
        context = CONTEXT_SHORTCUTS.get(self._focused_panel, [])
        shortcuts.extend(context)

        # Add panel focus shortcuts
        shortcuts.extend(PANEL_SHORTCUTS)

        # Add global shortcuts last
        shortcuts.extend(GLOBAL_SHORTCUTS)

        # Cap at maximum (Req 6.1)
        return shortcuts[:MAX_SHORTCUTS]

    def _render_shortcuts(self) -> None:
        """Render the shortcut bar with styled key-action pairs."""
        shortcuts = self._get_shortcuts()

        text = Text()
        for i, (key, action) in enumerate(shortcuts):
            if i > 0:
                text.append("  ", style="")

            text.append(key, style="bold cyan")
            text.append(f": {action}", style="grey50")

        self.update(text)
