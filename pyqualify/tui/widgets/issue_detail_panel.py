"""IssueDetailPanel widget for the PyQualify TUI dashboard.

Displays full details of a selected issue including title, severity,
check name, description, evidence, recommendation, and CWE/OWASP tags.

Requirements: 4.5, 4.6
"""

from __future__ import annotations

from rich.text import Text
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static

from pyqualify.models import Issue, Severity

# Severity color mapping consistent with the dashboard theme (Req 9.2)
SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "#ff5555",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "grey70",
}


class IssueDetailPanel(Widget):
    """Displays full details of a selected issue.

    Hidden by default (display: none). When an issue is selected via Enter
    on the IssuesTable, `show_issue()` renders the full details. Pressing
    Escape closes the panel via `hide()` and restores focus to the IssuesTable.

    Note: The actual Enter/Escape key event handling is wired in the
    DashboardScreen (task 4.2), not in this widget.
    """

    DEFAULT_CSS = """
    IssueDetailPanel {
        width: 100%;
        height: 100%;
        border: solid $secondary;
        border-title-color: $accent;
        border-title-align: right;
        padding: 1 2;
    }

    IssueDetailPanel:focus-within {
        border: solid $accent;
    }

    IssueDetailPanel #detail-scroll {
        height: 1fr;
        width: 100%;
    }

    IssueDetailPanel #detail-title {
        text-style: bold;
        width: 100%;
        padding: 0 0 1 0;
    }

    IssueDetailPanel #detail-meta {
        width: 100%;
        padding: 0 0 1 0;
    }

    IssueDetailPanel #detail-description-header {
        text-style: bold;
        color: white;
        padding: 1 0 0 0;
    }

    IssueDetailPanel #detail-description {
        width: 100%;
        padding: 0 0 1 0;
    }

    IssueDetailPanel #detail-evidence-header {
        text-style: bold;
        color: white;
        padding: 1 0 0 0;
    }

    IssueDetailPanel #detail-evidence {
        width: 100%;
        padding: 0 0 1 0;
    }

    IssueDetailPanel #detail-recommendation-header {
        text-style: bold;
        color: white;
        padding: 1 0 0 0;
    }

    IssueDetailPanel #detail-recommendation {
        width: 100%;
        padding: 0 0 1 0;
    }

    IssueDetailPanel #detail-tags {
        width: 100%;
        padding: 1 0 0 0;
        color: $text-muted;
    }
    """

    BORDER_TITLE = "Details"

    def __init__(
        self,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._current_issue: Issue | None = None

    def on_mount(self) -> None:
        """Hide the panel by default on mount."""
        self.display = False

    def compose(self):
        """Compose the detail panel with scrollable content sections."""
        with VerticalScroll(id="detail-scroll"):
            yield Static("", id="detail-title")
            yield Static("", id="detail-meta")
            yield Static("", id="detail-description-header")
            yield Static("", id="detail-description")
            yield Static("", id="detail-evidence-header")
            yield Static("", id="detail-evidence")
            yield Static("", id="detail-recommendation-header")
            yield Static("", id="detail-recommendation")
            yield Static("", id="detail-tags")

    def show_issue(self, issue: Issue) -> None:
        """Display full details of the given issue.

        Makes the panel visible and populates all sections with the issue's
        title, severity, check name, description, evidence (if present),
        recommendation (if present), and CWE/OWASP tags.

        Args:
            issue: The Issue object to display in detail.
        """
        self._current_issue = issue
        self.display = True

        # Title with severity color
        severity_color = SEVERITY_COLORS.get(issue.severity, "white")
        title_text = Text()
        title_text.append(f"[{issue.severity.value.upper()}] ", style=f"bold {severity_color}")
        title_text.append(issue.title, style="bold white")
        self.query_one("#detail-title", Static).update(title_text)

        # Meta line: check name and severity
        meta_text = Text()
        meta_text.append("Check: ", style="bold grey70")
        meta_text.append(issue.check, style="white")
        meta_text.append("  │  ", style="grey50")
        meta_text.append("Severity: ", style="bold grey70")
        meta_text.append(issue.severity.value.capitalize(), style=f"bold {severity_color}")
        self.query_one("#detail-meta", Static).update(meta_text)

        # Description section
        self.query_one("#detail-description-header", Static).update(
            Text("Description", style="bold white")
        )
        self.query_one("#detail-description", Static).update(
            Text(issue.description, style="white") if issue.description else Text("-", style="grey50")
        )

        # Evidence section (shown only if present)
        evidence_header = self.query_one("#detail-evidence-header", Static)
        evidence_body = self.query_one("#detail-evidence", Static)
        if issue.evidence:
            evidence_header.update(Text("Evidence", style="bold white"))
            evidence_body.update(Text(issue.evidence, style="grey85"))
            evidence_header.display = True
            evidence_body.display = True
        else:
            evidence_header.update("")
            evidence_body.update("")
            evidence_header.display = False
            evidence_body.display = False

        # Recommendation section (shown only if present)
        rec_header = self.query_one("#detail-recommendation-header", Static)
        rec_body = self.query_one("#detail-recommendation", Static)
        if issue.recommendation:
            rec_header.update(Text("Recommendation", style="bold white"))
            rec_body.update(Text(issue.recommendation, style="cyan"))
            rec_header.display = True
            rec_body.display = True
        else:
            rec_header.update("")
            rec_body.update("")
            rec_header.display = False
            rec_body.display = False

        # Tags section (CWE/OWASP)
        tags_text = Text()
        tags_parts: list[str] = []
        if issue.cwe:
            tags_parts.append(issue.cwe)
        if issue.owasp:
            tags_parts.append(issue.owasp)

        if tags_parts:
            tags_text.append("Tags: ", style="bold grey70")
            tags_text.append(", ".join(tags_parts), style="grey85")
        else:
            tags_text.append("Tags: ", style="bold grey70")
            tags_text.append("None", style="grey50")
        self.query_one("#detail-tags", Static).update(tags_text)

        # Scroll to top when showing a new issue
        scroll = self.query_one("#detail-scroll", VerticalScroll)
        scroll.scroll_home(animate=False)

    def hide(self) -> None:
        """Hide the detail panel.

        Sets display to none and clears the current issue reference.
        Called when the user presses Escape to close the detail view.
        """
        self.display = False
        self._current_issue = None

    @property
    def current_issue(self) -> Issue | None:
        """The issue currently being displayed, or None if hidden."""
        return self._current_issue

    @property
    def is_visible(self) -> bool:
        """Whether the detail panel is currently displayed."""
        return bool(self.display)
