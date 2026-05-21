"""Dashboard screens for the PyQualify TUI.

Implements the DashboardScreen which composes all widget panels into a
CSS grid layout. Handles responsive layout adaptation, terminal resize
events with panel content reflow, Enter key to show issue details, and
Escape key to hide the detail panel.

Requirements: 1.1, 1.2, 1.3, 1.4
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.events import Resize
from textual.screen import Screen

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
