"""IssuesTable widget for the PyQualify TUI dashboard.

Displays a scrollable, sortable table of analysis issues with severity icons,
severity level, title, check name, and CWE/OWASP tags.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.7
"""

from __future__ import annotations

from textual.widget import Widget
from textual.widgets import DataTable, Static
from textual.containers import Vertical
from textual.reactive import reactive

from pyqualify.models import Issue, Severity


# Maximum number of issues displayed in the table (Req 4.1)
MAX_ISSUES: int = 500

# Severity sort order: critical is highest priority (0), info is lowest (4)
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Severity display icons
SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

# Column identifiers
COLUMN_SEVERITY_ICON = "severity_icon"
COLUMN_SEVERITY = "severity"
COLUMN_TITLE = "title"
COLUMN_CHECK = "check"
COLUMN_TAGS = "tags"


class IssuesTable(Widget):
    """Scrollable, sortable table of analysis issues.

    Wraps a Textual DataTable to display issues with columns for severity icon,
    severity level, title, check name, and CWE/OWASP tags.

    Supports sorting by any column, keyboard scrolling (up/down for 1 row,
    page up/down for 10 rows), and displays an empty state message when
    no issues are present. Capped at 500 issues maximum.
    """

    DEFAULT_CSS = """
    IssuesTable {
        height: 100%;
        width: 100%;
    }

    IssuesTable #issues-data-table {
        height: 1fr;
        width: 100%;
    }

    IssuesTable #empty-state {
        width: 100%;
        height: 100%;
        content-align: center middle;
        color: $text-muted;
        text-align: center;
        padding: 2 0;
    }
    """

    # Reactive to track whether the table has issues
    _has_issues: reactive[bool] = reactive(False)

    # Current sort state
    _sort_column: str = COLUMN_SEVERITY
    _sort_ascending: bool = True

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._issues: list[Issue] = []

    def compose(self):
        """Compose the widget with a DataTable and an empty state message."""
        table = DataTable(id="issues-data-table")
        table.cursor_type = "row"
        table.zebra_stripes = True
        yield table
        yield Static(
            "No issues found. Run an analysis to see results here.",
            id="empty-state",
        )

    def on_mount(self) -> None:
        """Set up the DataTable columns on mount."""
        table = self.query_one("#issues-data-table", DataTable)
        table.add_columns(
            " ",          # Severity icon (narrow)
            "Severity",   # Severity level text
            "Title",      # Issue title
            "Check",      # Check name
            "Tags",       # CWE/OWASP tags
        )
        # Update visibility based on initial state
        self._update_visibility()

    def watch__has_issues(self, has_issues: bool) -> None:
        """Toggle visibility between table and empty state."""
        self._update_visibility()

    def _update_visibility(self) -> None:
        """Show/hide the table and empty state based on issue count."""
        try:
            table = self.query_one("#issues-data-table", DataTable)
            empty = self.query_one("#empty-state", Static)
        except Exception:
            return

        if self._has_issues:
            table.display = True
            empty.display = False
        else:
            table.display = False
            empty.display = True

    def populate(self, issues: list[Issue]) -> None:
        """Populate the table with a list of issues, replacing any existing data.

        Issues are sorted by the current sort settings and capped at 500.

        Args:
            issues: List of Issue objects to display.
        """
        # Cap at MAX_ISSUES
        self._issues = list(issues[:MAX_ISSUES])
        self._sort_issues()
        self._rebuild_table()
        self._has_issues = len(self._issues) > 0

    def append_issue(self, issue: Issue) -> None:
        """Append a single issue to the table during live analysis.

        If the table is already at the 500 issue cap, the issue is ignored.

        Args:
            issue: The Issue object to append.
        """
        if len(self._issues) >= MAX_ISSUES:
            return

        self._issues.append(issue)
        self._sort_issues()
        self._rebuild_table()
        self._has_issues = True

    def sort_by(self, column: str, ascending: bool = True) -> None:
        """Sort the table by the specified column.

        Args:
            column: Column identifier - one of "severity_icon", "severity",
                    "title", "check", or "tags".
            ascending: If True, sort ascending; if False, sort descending.
        """
        self._sort_column = column
        self._sort_ascending = ascending
        self._sort_issues()
        self._rebuild_table()

    def get_selected_issue(self) -> Issue | None:
        """Get the currently highlighted issue, or None if no selection.

        Returns:
            The Issue object for the currently selected row, or None.
        """
        if not self._issues:
            return None

        table = self.query_one("#issues-data-table", DataTable)
        cursor_row = table.cursor_row
        if 0 <= cursor_row < len(self._issues):
            return self._issues[cursor_row]
        return None

    def _sort_issues(self) -> None:
        """Sort the internal issues list based on current sort settings."""
        column = self._sort_column
        ascending = self._sort_ascending

        if column in (COLUMN_SEVERITY_ICON, COLUMN_SEVERITY):
            # Sort by severity order, secondary by title alphabetically
            self._issues.sort(
                key=lambda issue: (
                    SEVERITY_ORDER.get(issue.severity, 99),
                    issue.title.lower(),
                ),
                reverse=not ascending,
            )
        elif column == COLUMN_TITLE:
            self._issues.sort(
                key=lambda issue: issue.title.lower(),
                reverse=not ascending,
            )
        elif column == COLUMN_CHECK:
            self._issues.sort(
                key=lambda issue: issue.check.lower(),
                reverse=not ascending,
            )
        elif column == COLUMN_TAGS:
            self._issues.sort(
                key=lambda issue: self._format_tags(issue).lower(),
                reverse=not ascending,
            )

    def _rebuild_table(self) -> None:
        """Clear and rebuild all table rows from the internal issues list."""
        table = self.query_one("#issues-data-table", DataTable)
        table.clear()

        for issue in self._issues:
            icon = SEVERITY_ICONS.get(issue.severity, "⚪")
            severity_text = issue.severity.value.capitalize()
            title = issue.title
            check = issue.check
            tags = self._format_tags(issue)

            table.add_row(icon, severity_text, title, check, tags)

    @staticmethod
    def _format_tags(issue: Issue) -> str:
        """Format CWE and OWASP tags into a combined string.

        Args:
            issue: The Issue to extract tags from.

        Returns:
            A comma-separated string of CWE and OWASP identifiers,
            or "-" if none are present.
        """
        parts: list[str] = []
        if issue.cwe:
            parts.append(issue.cwe)
        if issue.owasp:
            parts.append(issue.owasp)
        return ", ".join(parts) if parts else "-"
