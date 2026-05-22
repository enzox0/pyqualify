"""Dashboard screens for the PyQualify TUI.

Implements the DashboardScreen which composes all widget panels into a
CSS grid layout. Handles responsive layout adaptation, terminal resize
events with panel content reflow, Enter key to show issue details, and
Escape key to hide the detail panel.

Also implements ToolSelectionScreen, a modal that lets the user pick an
analysis mode and enter a target before the dashboard is shown.

Also implements InterfaceSelectionScreen, a modal that lets the user
choose between CLI and TUI (Dashboard) interface modes on launch.

Requirements: 1.1, 1.2, 1.3, 1.4
"""

from __future__ import annotations

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical
from textual.events import Key, Resize
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Input, Label, Static

from pyqualify.models import AnalysisMode
from pyqualify.tui.widgets import (
    HeaderPanel,
    IssueDetailPanel,
    IssuesTable,
    LogPanel,
    MetricsPanel,
    NavigationBar,
)


# Minimum terminal width for the multi-panel layout (Req 1.2)
MIN_TERMINAL_WIDTH: int = 80
# Minimum terminal height for the multi-panel layout (Req 1.5)
MIN_TERMINAL_HEIGHT: int = 24
# Minimum column width for any panel (Req 1.2)
MIN_PANEL_WIDTH: int = 20


# ---------------------------------------------------------------------------
# Interface Selection Screen (CLI vs TUI)
# ---------------------------------------------------------------------------


class InterfaceSelectionScreen(ModalScreen[str]):
    """Modal screen that lets the user choose between CLI and TUI interface.

    Dismissed with "cli" or "tui" string when the user confirms,
    or exits the app when Escape / q is pressed.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Quit", show=True),
        Binding("q", "cancel", "Quit", show=False),
        Binding("1", "select_cli", "CLI", show=False, priority=True),
        Binding("2", "select_tui", "TUI", show=False, priority=True),
        Binding("up", "prev_option", "Prev", show=False, priority=True),
        Binding("down", "next_option", "Next", show=False, priority=True),
        Binding("enter", "confirm", "Confirm", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    InterfaceSelectionScreen {
        align: center middle;
        background: #0d0d0d;
    }

    #interface-container {
        background: #111111;
        border: solid cyan;
        padding: 1 2;
        width: 55%;
        min-width: 52;
        max-width: 72;
        height: auto;
    }

    #interface-title {
        color: cyan;
        text-style: bold;
        text-align: center;
        height: 1;
    }

    #interface-subtitle {
        color: #555555;
        text-align: center;
        height: 1;
        margin: 0 0 1 0;
    }

    .interface-btn {
        width: 100%;
        height: 1;
        background: #1a1a1a;
        color: #888888;
        padding: 0 1;
    }

    .interface-btn:hover {
        background: #0a2030;
        color: cyan;
    }

    .interface-btn.-active {
        background: #0a2030;
        color: cyan;
    }

    #interface-hint {
        color: #333333;
        text-align: center;
        height: 1;
        margin: 1 0 0 0;
    }
    """

    _INTERFACE_OPTIONS: list[tuple[str, str, str]] = [
        ("cli", "1  CLI",       "Classic terminal output with progress indicators"),
        ("tui", "2  Dashboard", "Interactive TUI with live panels and real-time updates"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._selected: str = "cli"

    def compose(self) -> ComposeResult:
        with Vertical(id="interface-container"):
            yield Static("PyQualify", id="interface-title")
            yield Static("Choose your interface", id="interface-subtitle")

            for key, label, desc in self._INTERFACE_OPTIONS:
                active = " -active" if key == self._selected else ""
                yield Static(
                    f"  {label}  —  {desc}",
                    id=f"iface-btn-{key}",
                    classes=f"interface-btn{active}",
                )

            yield Static("1/2 select  •  Enter confirm  •  Esc quit", id="interface-hint")

    def _set_option(self, option: str) -> None:
        """Switch the active option and update button styles."""
        self._selected = option
        for key, _, _ in self._INTERFACE_OPTIONS:
            btn = self.query_one(f"#iface-btn-{key}", Static)
            if key == option:
                btn.add_class("-active")
            else:
                btn.remove_class("-active")

    def action_select_cli(self) -> None:
        self._set_option("cli")

    def action_select_tui(self) -> None:
        self._set_option("tui")

    def action_prev_option(self) -> None:
        options = [opt[0] for opt in self._INTERFACE_OPTIONS]
        idx = options.index(self._selected)
        self._set_option(options[(idx - 1) % len(options)])

    def action_next_option(self) -> None:
        options = [opt[0] for opt in self._INTERFACE_OPTIONS]
        idx = options.index(self._selected)
        self._set_option(options[(idx + 1) % len(options)])

    def action_confirm(self) -> None:
        self.dismiss(self._selected)

    def action_cancel(self) -> None:
        self.app.exit(return_code=0)

    def on_key(self, event: Key) -> None:
        """Handle keys at screen level."""
        if event.key == "1":
            event.stop()
            event.prevent_default()
            self.action_select_cli()
        elif event.key == "2":
            event.stop()
            event.prevent_default()
            self.action_select_tui()
        elif event.key == "up":
            event.stop()
            event.prevent_default()
            self.action_prev_option()
        elif event.key == "down":
            event.stop()
            event.prevent_default()
            self.action_next_option()
        elif event.key == "enter":
            event.stop()
            event.prevent_default()
            self.action_confirm()

    def on_static_click(self, event: Static.Clicked) -> None:
        """Handle clicks on the option rows."""
        widget_id = event.widget.id
        if widget_id == "iface-btn-cli":
            self._set_option("cli")
            self.dismiss("cli")
        elif widget_id == "iface-btn-tui":
            self._set_option("tui")
            self.dismiss("tui")


class InterfaceSelectorApp(App[str]):
    """Minimal Textual app that shows the interface selection screen.

    Returns "cli" or "tui" as the app result, which the CLI entry point
    uses to decide which flow to launch.
    """

    CSS = """
    Screen {
        background: #0d0d0d;
    }
    """

    ENABLE_COMMAND_PALETTE = False

    def on_mount(self) -> None:
        """Push the interface selection screen on mount."""
        self.push_screen(
            InterfaceSelectionScreen(),
            callback=self._on_selection,
        )

    def _on_selection(self, result: str | None) -> None:
        """Handle the selection result."""
        if result is None:
            self.exit(return_code=0)
        else:
            self.exit(result=result)


# ---------------------------------------------------------------------------
# Tool Selection Screen
# ---------------------------------------------------------------------------

_TOOL_OPTIONS: list[tuple[str, str, str]] = [
    ("web",  "1  Web",  "Security, SEO, accessibility & performance"),
    ("code", "2  Code", "Vulnerabilities, quality & test gaps"),
    ("api",  "3  API",  "REST endpoint security & integrity"),
]

_TARGET_HINTS: dict[str, str] = {
    "web":  "https://example.com",
    "code": "./src",
    "api":  "https://api.example.com",
}

_TARGET_LABELS: dict[str, str] = {
    "web":  "Target URL",
    "code": "Path to file or directory",
    "api":  "API base URL",
}


# ---------------------------------------------------------------------------
# Path Auto-Suggestion
# ---------------------------------------------------------------------------

from pathlib import Path as _Path
from textual.suggester import Suggester as _Suggester


class PathSuggester(_Suggester):
    """Provides filesystem path auto-suggestions based on user input.

    As the user types a path, this suggester lists matching files and
    directories in the current or specified parent directory and returns
    the best match as a completion suggestion (ghost text).
    """

    def __init__(self) -> None:
        super().__init__(use_cache=False, case_sensitive=False)

    async def get_suggestion(self, value: str) -> str | None:
        """Get a path completion suggestion for the current input value.

        Args:
            value: The current text in the input field.

        Returns:
            A full path suggestion string, or None if no match found.
        """
        if not value:
            return None

        try:
            input_path = _Path(value)

            # Determine the directory to search and the prefix to match
            if value.endswith("/") or value.endswith("\\"):
                # User typed a directory separator - list contents of that dir
                search_dir = input_path
                prefix = ""
            else:
                # User is typing a name - search in the parent directory
                search_dir = input_path.parent
                prefix = input_path.name.lower()

            # Resolve relative to cwd
            resolved_dir = search_dir
            if not resolved_dir.is_absolute():
                resolved_dir = _Path.cwd() / resolved_dir

            if not resolved_dir.is_dir():
                return None

            # List directory contents and find matches
            matches: list[str] = []
            try:
                for entry in sorted(resolved_dir.iterdir()):
                    name = entry.name
                    # Skip hidden files/dirs
                    if name.startswith("."):
                        continue
                    if prefix and not name.lower().startswith(prefix):
                        continue
                    matches.append(name)
            except PermissionError:
                return None

            if not matches:
                return None

            # Return the first match as a full path suggestion
            best_match = matches[0]

            # Build the suggestion preserving the user's path prefix
            if value.endswith("/") or value.endswith("\\"):
                suggestion = value + best_match
            else:
                # Determine the separator used in the input
                if "/" in value:
                    sep = "/"
                elif "\\" in value:
                    sep = "\\"
                else:
                    sep = "/"

                # Get the parent portion as the user typed it
                parent_part = value[:len(value) - len(input_path.name)]
                suggestion = parent_part + best_match

            # Add trailing separator if it's a directory
            suggested_full = resolved_dir / best_match
            if suggested_full.is_dir() and not suggestion.endswith(("/", "\\")):
                sep = "/"
                if "\\" in value:
                    sep = "\\"
                suggestion += sep

            return suggestion

        except (OSError, ValueError):
            return None


class _ModeAwareInput(Input):
    """Input subclass that intercepts 1/2/3 and up/down keys.

    When the input is empty (user hasn't started typing a URL), these
    keys trigger mode selection. Once the user has typed content, only
    up/down are intercepted (1/2/3 are allowed as normal text for URLs).

    Supports a PathSuggester for filesystem auto-completion in code mode.
    The suggestion appears as ghost text and can be accepted with Tab or
    the right arrow key.
    """

    def _on_key(self, event: Key) -> None:
        screen = self.screen
        # Tab accepts the suggestion (handled by Input natively)
        # Always intercept up/down for mode navigation
        if event.key in ("up", "down"):
            event.stop()
            event.prevent_default()
            if event.key == "up":
                screen.action_prev_mode()
            else:
                screen.action_next_mode()
            return
        # Intercept 1/2/3 only when input is empty (mode selection)
        if event.key in ("1", "2", "3") and not self.value:
            event.stop()
            event.prevent_default()
            if event.key == "1":
                screen.action_select_web()
            elif event.key == "2":
                screen.action_select_code()
            elif event.key == "3":
                screen.action_select_api()
            return
        super()._on_key(event)


class ToolSelectionScreen(ModalScreen[tuple[AnalysisMode, str]]):
    """Modal screen that lets the user choose an analysis mode and target.

    Dismissed with a (AnalysisMode, target) tuple when the user confirms,
    or exits the app when Escape / q is pressed.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Quit", show=True),
        Binding("q", "cancel", "Quit", show=False),
        Binding("1", "select_web", "Web", show=False, priority=True),
        Binding("2", "select_code", "Code", show=False, priority=True),
        Binding("3", "select_api", "API", show=False, priority=True),
        Binding("up", "prev_mode", "Prev", show=False, priority=True),
        Binding("down", "next_mode", "Next", show=False, priority=True),
    ]

    DEFAULT_CSS = """
    ToolSelectionScreen {
        align: center middle;
        background: #0d0d0d;
    }

    #selection-container {
        background: #111111;
        border: solid cyan;
        padding: 1 2;
        width: 55%;
        min-width: 52;
        max-width: 72;
        height: auto;
    }

    #selection-title {
        color: cyan;
        text-style: bold;
        text-align: center;
        height: 1;
    }

    #selection-subtitle {
        color: #555555;
        text-align: center;
        height: 1;
        margin: 0 0 1 0;
    }

    .tool-btn {
        width: 100%;
        height: 1;
        background: #1a1a1a;
        color: #888888;
        padding: 0 1;
    }

    .tool-btn:hover {
        background: #0a2030;
        color: cyan;
    }

    .tool-btn.-active {
        background: #0a2030;
        color: cyan;
    }

    #target-label {
        color: #555555;
        height: 1;
        margin: 1 0 0 0;
    }

    #target-input {
        width: 100%;
        height: 3;
        background: #1a1a1a;
        border: solid #333333;
        color: white;
        padding: 0 1;
    }

    #target-input:focus {
        border: solid cyan;
    }

    #error-label {
        color: red;
        height: 1;
    }

    #confirm-btn {
        width: 100%;
        min-height: 1;
        background: #0a1a0a;
        border: solid #28a745;
        color: #28a745;
        margin: 0;
    }

    #confirm-btn:focus {
        background: #0a2a1a;
        border: solid green;
        color: green;
    }

    #hint-label {
        color: #333333;
        text-align: center;
        height: 1;
        margin: 1 0 0 0;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._selected_mode: str = "web"

    def compose(self) -> ComposeResult:
        with Vertical(id="selection-container"):
            yield Static("PyQualify", id="selection-title")
            yield Static("Select an analysis mode to get started", id="selection-subtitle")

            for mode_key, label, desc in _TOOL_OPTIONS:
                active = " -active" if mode_key == self._selected_mode else ""
                yield Static(
                    f"  {label}  —  {desc}",
                    id=f"btn-{mode_key}",
                    classes=f"tool-btn{active}",
                )

            yield Static(_TARGET_LABELS[self._selected_mode], id="target-label")
            # Use PathSuggester for code mode, None for URL modes
            suggester = PathSuggester() if self._selected_mode == "code" else None
            yield _ModeAwareInput(
                placeholder=_TARGET_HINTS[self._selected_mode],
                suggester=suggester,
                id="target-input",
            )
            yield Static("", id="error-label")
            yield Button("Analyze  ↵", id="confirm-btn")
            yield Static("1/2/3 select mode  •  Tab navigate  •  Esc quit", id="hint-label")

    # ── Mode selection helpers ──────────────────────────────────────────────

    def _set_mode(self, mode: str) -> None:
        """Switch the active mode, update button styles and input hint."""
        self._selected_mode = mode

        for mode_key, _, _ in _TOOL_OPTIONS:
            btn = self.query_one(f"#btn-{mode_key}", Static)
            if mode_key == mode:
                btn.add_class("-active")
            else:
                btn.remove_class("-active")

        label = self.query_one("#target-label", Static)
        label.update(_TARGET_LABELS[mode])

        inp = self.query_one("#target-input", _ModeAwareInput)
        inp.placeholder = _TARGET_HINTS[mode]
        inp.value = ""
        # Swap suggester: PathSuggester for code mode, None for URL modes
        inp.suggester = PathSuggester() if mode == "code" else None
        inp.focus()

        self._clear_error()

    def _clear_error(self) -> None:
        self.query_one("#error-label", Static).update("")

    def _show_error(self, msg: str) -> None:
        self.query_one("#error-label", Static).update(f"✖ {msg}")

    # ── Keyboard shortcuts for mode selection ──────────────────────────────

    def action_select_web(self) -> None:
        self._set_mode("web")

    def action_select_code(self) -> None:
        self._set_mode("code")

    def action_select_api(self) -> None:
        self._set_mode("api")

    def action_prev_mode(self) -> None:
        modes = [opt[0] for opt in _TOOL_OPTIONS]
        idx = modes.index(self._selected_mode)
        self._set_mode(modes[(idx - 1) % len(modes)])

    def action_next_mode(self) -> None:
        modes = [opt[0] for opt in _TOOL_OPTIONS]
        idx = modes.index(self._selected_mode)
        self._set_mode(modes[(idx + 1) % len(modes)])

    def action_cancel(self) -> None:
        self.app.exit(return_code=0)

    def on_key(self, event: Key) -> None:
        """Handle keys at screen level for when focus is NOT on the input."""
        # Don't double-handle if the input already handled it
        if isinstance(self.focused, _ModeAwareInput):
            return
        if event.key == "1":
            event.stop()
            event.prevent_default()
            self.action_select_web()
        elif event.key == "2":
            event.stop()
            event.prevent_default()
            self.action_select_code()
        elif event.key == "3":
            event.stop()
            event.prevent_default()
            self.action_select_api()
        elif event.key == "up":
            event.stop()
            event.prevent_default()
            self.action_prev_mode()
        elif event.key == "down":
            event.stop()
            event.prevent_default()
            self.action_next_mode()

    # ── Button clicks ──────────────────────────────────────────────────────

    def on_static_click(self, event: Static.Clicked) -> None:
        """Handle clicks on the mode Static rows."""
        widget_id = event.widget.id
        if widget_id == "btn-web":
            self._set_mode("web")
        elif widget_id == "btn-code":
            self._set_mode("code")
        elif widget_id == "btn-api":
            self._set_mode("api")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "confirm-btn":
            self._confirm()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Allow pressing Enter in the input field to confirm."""
        self._confirm()

    def _confirm(self) -> None:
        """Validate the target and dismiss with (mode, target)."""
        from pyqualify.cli.validators import validate_url, validate_path
        import click

        target = self.query_one("#target-input", _ModeAwareInput).value.strip()
        if not target:
            self._show_error("Target cannot be empty.")
            self.query_one("#target-input", _ModeAwareInput).focus()
            return

        try:
            if self._selected_mode in ("web", "api"):
                target = validate_url(target)
            else:
                target = validate_path(target)
        except click.BadParameter as e:
            self._show_error(e.format_message())
            self.query_one("#target-input", _ModeAwareInput).focus()
            return

        self.dismiss((AnalysisMode(self._selected_mode), target))


# ---------------------------------------------------------------------------
# Dashboard Screen
# ---------------------------------------------------------------------------


class DashboardScreen(Screen):
    """Main dashboard screen composing all panels via a CSS grid layout.

    Uses a Container with id="dashboard-grid" that matches the TCSS grid
    layout defined in dashboard.tcss. Composes HeaderPanel, MetricsPanel,
    IssuesTable, IssueDetailPanel, LogPanel, and NavigationBar.

    Handles:
    - Terminal resize events with panel content reflow (Req 1.3)
    - Enter key on IssuesTable to show IssueDetailPanel
    - Escape key to hide IssueDetailPanel and restore focus to IssuesTable
    - Responsive layout that adapts to terminal dimensions
    - Truncation indicators (ellipsis) for clipped content via CSS overflow
    """

    BINDINGS = [
        Binding("escape", "close_detail", "Close Detail", show=False),
    ]

    def compose(self) -> ComposeResult:
        """Compose all panels within the dashboard grid container."""
        with Container(id="dashboard-grid"):
            yield HeaderPanel(id="header-panel")
            yield MetricsPanel(id="metrics-panel", classes="panel")
            yield IssuesTable(id="issues-table", classes="panel")
            yield IssueDetailPanel(id="issue-detail-panel")
            yield LogPanel(id="log-panel", classes="panel")
            yield NavigationBar(id="navigation-bar")

    def on_mount(self) -> None:
        """Validate terminal dimensions and set up responsive behavior."""
        self._check_terminal_dimensions()

    def on_resize(self, event: Resize) -> None:
        """Handle terminal resize events to reflow panel content.

        Requirement 1.3: Reflow panel content to fit new dimensions within
        1 second, maintaining all panel borders as closed rectangles,
        preserving all panel title text, and displaying no garbled or
        overlapping characters.

        Textual's CSS grid layout handles the structural reflow (panel
        positioning and sizing). This handler ensures:
        1. Terminal still meets minimum dimension requirements
        2. All panels with custom render() methods refresh their content
           to fit the new available width (e.g., MetricsPanel progress bar)
        3. The HeaderPanel re-renders its status line for the new width
        4. The NavigationBar re-renders its shortcut display

        Args:
            event: The Resize event containing the new terminal dimensions.
        """
        self._check_terminal_dimensions()
        self._reflow_panels()

    def _reflow_panels(self) -> None:
        """Refresh all panel widgets to reflow content for new dimensions.

        Triggers a refresh on each panel that uses custom rendering logic,
        ensuring their content adapts to the new available space. Textual's
        layout engine recalculates widget sizes from the CSS grid, and
        refresh() causes each widget to re-invoke its render() method with
        the updated dimensions.

        This ensures:
        - MetricsPanel progress bar width adapts to available space
        - HeaderPanel status indicators reflow without truncation
        - LogPanel entries wrap correctly at new widths
        - NavigationBar shortcuts fit the new footer width
        - All panel borders remain as closed rectangles (handled by
          Textual's border rendering which always draws complete boxes)
        - Panel titles are preserved (they are part of widget content,
          not affected by resize)
        - No garbled or overlapping characters (refresh clears and
          redraws each widget cleanly)
        """
        # Refresh panels with custom render() methods
        try:
            self.query_one("#header-panel", HeaderPanel).refresh()
        except Exception:
            pass

        try:
            self.query_one("#metrics-panel", MetricsPanel).refresh()
        except Exception:
            pass

        try:
            self.query_one("#issues-table", IssuesTable).refresh()
        except Exception:
            pass

        try:
            self.query_one("#log-panel", LogPanel).refresh()
        except Exception:
            pass

        try:
            self.query_one("#navigation-bar", NavigationBar).refresh()
        except Exception:
            pass

        # Refresh the issue detail panel if it's currently visible
        try:
            detail_panel = self.query_one(
                "#issue-detail-panel", IssueDetailPanel
            )
            if detail_panel.has_class("visible"):
                detail_panel.refresh()
        except Exception:
            pass

    def _check_terminal_dimensions(self) -> None:
        """Check if terminal meets minimum dimension requirements.

        If the terminal is below 80 columns or 24 rows, display a warning
        message and exit the app with a non-zero code (Req 1.5, 10.2).
        """
        size = self.app.size
        if size.width < MIN_TERMINAL_WIDTH or size.height < MIN_TERMINAL_HEIGHT:
            self.app.bell()
            self.notify(
                f"Terminal too small ({size.width}x{size.height}). "
                f"Minimum required: {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT}. "
                f"Please resize your terminal.",
                severity="error",
                timeout=5,
            )
            self.app.exit(return_code=1)

    def on_data_table_row_selected(self) -> None:
        """Handle Enter key press on a row in the IssuesTable.

        Shows the IssueDetailPanel with the selected issue's full details
        (Req 4.5).
        """
        issues_table = self.query_one("#issues-table", IssuesTable)
        issue = issues_table.get_selected_issue()
        if issue is None:
            return

        detail_panel = self.query_one("#issue-detail-panel", IssueDetailPanel)
        detail_panel.show_issue(issue)
        detail_panel.add_class("visible")
        detail_panel.focus()

    def action_close_detail(self) -> None:
        """Close the IssueDetailPanel and restore focus to IssuesTable.

        Triggered by Escape key when the detail panel is visible (Req 4.6).
        """
        detail_panel = self.query_one("#issue-detail-panel", IssueDetailPanel)
        if detail_panel.is_visible:
            detail_panel.hide()
            detail_panel.remove_class("visible")
            # Restore focus to the IssuesTable
            issues_table = self.query_one("#issues-table", IssuesTable)
            issues_table.focus()
