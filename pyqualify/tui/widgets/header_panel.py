"""HeaderPanel widget for the PyQualify TUI dashboard.

Displays the PyQualify banner/title, version, and three status indicators
for AI engine, analyzer, and analysis state. Each indicator uses colored
symbols to convey component health at a glance.

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import Static

from pyqualify.tui.models import StatusState

# Version displayed in the header
VERSION = "0.2.0b1"

# Status state to symbol/color mapping (Req 2.2-2.9)
STATUS_SYMBOLS: dict[str, tuple[str, str]] = {
    "ready": ("●", "green"),           # Green filled circle (Req 2.2, 2.4)
    "setup_needed": ("○", "yellow"),   # Yellow hollow circle (Req 2.3, 2.5)
    "idle": ("○", "grey50"),           # Gray hollow circle (Req 2.6)
    "running": ("⠋", "cyan"),          # Cyan spinner character (Req 2.7)
    "complete": ("✓", "green"),        # Green checkmark (Req 2.8)
    "error": ("✗", "red"),             # Red cross (Req 2.9)
}

# Spinner frames for the running state animation (Req 2.7)
SPINNER_FRAMES: list[str] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class HeaderPanel(Static):
    """Displays the PyQualify banner, version, and status indicators.

    Shows three status indicators for system components:
    - ai_engine: AI engine configuration state
    - analyzer: Active analyzer availability
    - analysis: Current analysis run state

    Each indicator renders a colored symbol with a text label reflecting
    the component's current state.
    """

    DEFAULT_CSS = """
    HeaderPanel {
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
        self._statuses: dict[str, StatusState] = {
            "ai_engine": StatusState(
                component="ai_engine", state="idle", label="AI Engine"
            ),
            "analyzer": StatusState(
                component="analyzer", state="idle", label="Analyzer"
            ),
            "analysis": StatusState(
                component="analysis", state="idle", label="idle"
            ),
        }
        self._spinner_index: int = 0
        self._spinner_timer = None

    def on_mount(self) -> None:
        """Initialize the header content on mount."""
        self._render_header()

    def update_status(self, component: str, state: str, label: str) -> None:
        """Update a status indicator for a given component.

        Args:
            component: Component identifier - "ai_engine", "analyzer", or "analysis".
            state: New state - "ready", "setup_needed", "idle", "running",
                   "complete", or "error".
            label: Human-readable label to display alongside the status symbol.
        """
        if component not in self._statuses:
            return

        self._statuses[component] = StatusState(
            component=component, state=state, label=label
        )

        # Manage spinner animation for running state (Req 2.7)
        has_running = any(s.state == "running" for s in self._statuses.values())
        if has_running and self._spinner_timer is None:
            self._start_spinner()
        elif not has_running and self._spinner_timer is not None:
            self._stop_spinner()

        self._render_header()

    def _start_spinner(self) -> None:
        """Start the spinner animation timer (≥4 fps → every 0.1s)."""
        self._spinner_index = 0
        self._spinner_timer = self.set_interval(0.1, self._advance_spinner)

    def _stop_spinner(self) -> None:
        """Stop the spinner animation timer."""
        if self._spinner_timer is not None:
            self._spinner_timer.stop()
            self._spinner_timer = None

    def _advance_spinner(self) -> None:
        """Advance the spinner frame and re-render."""
        self._spinner_index = (self._spinner_index + 1) % len(SPINNER_FRAMES)
        self._render_header()

    def _render_header(self) -> None:
        """Render the full header content with banner and status indicators."""
        text = Text()

        # Banner / Title
        text.append("PyQualify", style="bold cyan")
        text.append(f" v{VERSION}", style="grey70")
        text.append("  │  ", style="grey37")

        # Status indicators
        for i, (component, status) in enumerate(self._statuses.items()):
            if i > 0:
                text.append("  ", style="")

            symbol, color = self._get_symbol_and_color(status)
            text.append(symbol, style=f"bold {color}")
            text.append(f" {status.label}", style=color)

        self.update(text)

    def _get_symbol_and_color(self, status: StatusState) -> tuple[str, str]:
        """Get the display symbol and color for a status state.

        Args:
            status: The StatusState to get the symbol for.

        Returns:
            A tuple of (symbol, color) for Rich text rendering.
        """
        if status.state == "running":
            # Use animated spinner frame
            symbol = SPINNER_FRAMES[self._spinner_index]
            return symbol, "cyan"

        symbol, color = STATUS_SYMBOLS.get(status.state, ("?", "grey50"))
        return symbol, color
