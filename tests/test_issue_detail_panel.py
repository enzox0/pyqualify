"""Tests for IssueDetailPanel widget."""

import pytest

from textual.app import App, ComposeResult

from pyqualify.models import Issue, Severity
from pyqualify.tui.widgets.issue_detail_panel import IssueDetailPanel


class DetailPanelApp(App[None]):
    """Minimal app for testing IssueDetailPanel."""

    def compose(self) -> ComposeResult:
        yield IssueDetailPanel(id="detail")


@pytest.fixture
def full_issue() -> Issue:
    """Create a fully populated issue for testing."""
    return Issue(
        check="missing-csp",
        severity=Severity.HIGH,
        title="Missing Content-Security-Policy Header",
        description="The application does not set a Content-Security-Policy header.",
        evidence="HTTP response headers: Server: nginx, X-Frame-Options: DENY",
        recommendation="Add a strict CSP header to prevent XSS attacks.",
        cwe="CWE-693",
        owasp="A05:2021",
    )


@pytest.fixture
def minimal_issue() -> Issue:
    """Create an issue with no optional fields populated."""
    return Issue(
        check="info-disclosure",
        severity=Severity.INFO,
        title="Server Version Disclosed",
        description="The server discloses its version in response headers.",
        evidence="",
        recommendation="",
        cwe=None,
        owasp=None,
    )


@pytest.mark.asyncio
async def test_panel_hidden_by_default():
    """Panel should be hidden (display: none) on mount."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        # display is False means display: none
        assert panel.display is False


@pytest.mark.asyncio
async def test_show_issue_makes_panel_visible(full_issue: Issue):
    """Calling show_issue should make the panel visible."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(full_issue)
        assert panel.display is True


@pytest.mark.asyncio
async def test_show_issue_stores_current_issue(full_issue: Issue):
    """show_issue should store the issue as current_issue."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(full_issue)
        assert panel.current_issue is full_issue


@pytest.mark.asyncio
async def test_hide_makes_panel_invisible(full_issue: Issue):
    """Calling hide should set display to none and clear current issue."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(full_issue)
        assert panel.display is True

        panel.hide()
        assert panel.display is False
        assert panel.current_issue is None


@pytest.mark.asyncio
async def test_show_issue_with_all_fields(full_issue: Issue):
    """Panel should display all fields when issue has full data."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(full_issue)

        # Evidence and recommendation sections should be visible
        from textual.widgets import Static

        evidence_header = panel.query_one("#detail-evidence-header", Static)
        evidence_body = panel.query_one("#detail-evidence", Static)
        rec_header = panel.query_one("#detail-recommendation-header", Static)
        rec_body = panel.query_one("#detail-recommendation", Static)

        assert evidence_header.display is True
        assert evidence_body.display is True
        assert rec_header.display is True
        assert rec_body.display is True


@pytest.mark.asyncio
async def test_show_issue_hides_empty_evidence(minimal_issue: Issue):
    """Panel should hide evidence section when evidence is empty."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(minimal_issue)

        from textual.widgets import Static

        evidence_header = panel.query_one("#detail-evidence-header", Static)
        evidence_body = panel.query_one("#detail-evidence", Static)

        assert evidence_header.display is False
        assert evidence_body.display is False


@pytest.mark.asyncio
async def test_show_issue_hides_empty_recommendation(minimal_issue: Issue):
    """Panel should hide recommendation section when recommendation is empty."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        panel.show_issue(minimal_issue)

        from textual.widgets import Static

        rec_header = panel.query_one("#detail-recommendation-header", Static)
        rec_body = panel.query_one("#detail-recommendation", Static)

        assert rec_header.display is False
        assert rec_body.display is False


@pytest.mark.asyncio
async def test_is_visible_property(full_issue: Issue):
    """is_visible property should reflect panel display state."""
    async with DetailPanelApp().run_test() as pilot:
        panel = pilot.app.query_one("#detail", IssueDetailPanel)
        assert panel.is_visible is False

        panel.show_issue(full_issue)
        assert panel.is_visible is True

        panel.hide()
        assert panel.is_visible is False
