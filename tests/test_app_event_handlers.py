"""Unit tests for DashboardApp event handlers (Task 5.2).

Tests cover:
- on_progress_update: updates HeaderPanel status with phase and percentage
- on_issue_discovered: appends issue to IssuesTable, updates MetricsPanel counts
- on_log_emitted: appends entry to LogPanel
- on_analysis_complete: updates MetricsPanel, applies highlight, sets status
- on_analysis_error: updates status to error, logs error to LogPanel

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 2.8, 2.9
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pyqualify.container import Container
from pyqualify.models import (
    AnalysisMetadata,
    AnalysisMode,
    AnalysisResult,
    Issue,
    RiskLevel,
    Severity,
)
from pyqualify.tui.app import DashboardApp
from pyqualify.tui.messages import (
    AnalysisComplete,
    AnalysisError,
    IssueDiscovered,
    LogEmitted,
    ProgressUpdate,
)
from pyqualify.tui.widgets.header_panel import HeaderPanel
from pyqualify.tui.widgets.issues_table import IssuesTable
from pyqualify.tui.widgets.log_panel import LogPanel
from pyqualify.tui.widgets.metrics_panel import MetricsPanel


@pytest.fixture
def mock_container():
    """Create a mock Container for DashboardApp."""
    return MagicMock(spec=Container)


@pytest.fixture
def sample_issue():
    """Create a sample Issue for testing."""
    return Issue(
        check="missing-csp-header",
        severity=Severity.HIGH,
        title="Missing Content-Security-Policy",
        description="The CSP header is not set.",
        evidence="Header not found in response",
        recommendation="Add a CSP header",
    )


@pytest.fixture
def sample_result(sample_issue):
    """Create a sample AnalysisResult for testing."""
    return AnalysisResult(
        score=85,
        grade="B",
        risk_level=RiskLevel.MEDIUM,
        issues=[sample_issue],
        summary="Analysis found 1 issue.",
        metadata=AnalysisMetadata(
            timestamp="2024-01-01T00:00:00Z",
            target="https://example.com",
            mode=AnalysisMode.WEB,
        ),
    )


@pytest.fixture
def dashboard_app(mock_container):
    """Create a DashboardApp instance for testing."""
    return DashboardApp(container=mock_container)


class TestOnProgressUpdate:
    """Tests for on_progress_update handler (Req 7.3)."""

    @pytest.mark.asyncio
    async def test_updates_header_status_with_phase_and_percent(
        self, dashboard_app: DashboardApp
    ):
        """ProgressUpdate should update the HeaderPanel with phase and percentage."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            # Wait for the DashboardScreen to mount with its widgets
            await pilot.pause(0.5)

            # Query from the screen which has the widgets
            screen = dashboard_app.screen
            header = screen.query_one("#header-panel", HeaderPanel)

            msg = ProgressUpdate(phase="scanning", percent=45)
            dashboard_app.on_progress_update(msg)

            # Verify the analysis status was updated to running with the label
            status = header._statuses["analysis"]
            assert status.state == "running"
            assert "scanning" in status.label
            assert "45%" in status.label

    @pytest.mark.asyncio
    async def test_keeps_running_state_active(
        self, dashboard_app: DashboardApp
    ):
        """ProgressUpdate should keep the status in 'running' state."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            header = screen.query_one("#header-panel", HeaderPanel)

            msg = ProgressUpdate(phase="enriching", percent=80)
            dashboard_app.on_progress_update(msg)

            assert header._statuses["analysis"].state == "running"


class TestOnIssueDiscovered:
    """Tests for on_issue_discovered handler (Req 7.2)."""

    @pytest.mark.asyncio
    async def test_appends_issue_to_issues_table(
        self, dashboard_app: DashboardApp, sample_issue: Issue
    ):
        """IssueDiscovered should append the issue to the IssuesTable."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            issues_table = screen.query_one("#issues-table", IssuesTable)

            msg = IssueDiscovered(issue=sample_issue)
            dashboard_app.on_issue_discovered(msg)

            assert len(issues_table._issues) == 1
            assert issues_table._issues[0].check == "missing-csp-header"

    @pytest.mark.asyncio
    async def test_updates_metrics_panel_issue_counts(
        self, dashboard_app: DashboardApp, sample_issue: Issue
    ):
        """IssueDiscovered should increment the issue count in MetricsPanel."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            metrics_panel = screen.query_one("#metrics-panel", MetricsPanel)

            msg = IssueDiscovered(issue=sample_issue)
            dashboard_app.on_issue_discovered(msg)

            counts = metrics_panel.issue_counts
            assert counts["high"] == 1

    @pytest.mark.asyncio
    async def test_multiple_issues_increment_counts(
        self, dashboard_app: DashboardApp
    ):
        """Multiple IssueDiscovered messages should accumulate counts."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            metrics_panel = screen.query_one("#metrics-panel", MetricsPanel)

            issue1 = Issue(
                check="check-1",
                severity=Severity.HIGH,
                title="Issue 1",
                description="Desc",
                evidence="Evidence",
                recommendation="Fix it",
            )
            issue2 = Issue(
                check="check-2",
                severity=Severity.CRITICAL,
                title="Issue 2",
                description="Desc",
                evidence="Evidence",
                recommendation="Fix it",
            )

            dashboard_app.on_issue_discovered(IssueDiscovered(issue=issue1))
            dashboard_app.on_issue_discovered(IssueDiscovered(issue=issue2))

            counts = metrics_panel.issue_counts
            assert counts["high"] == 1
            assert counts["critical"] == 1


class TestOnLogEmitted:
    """Tests for on_log_emitted handler (Req 7.1)."""

    @pytest.mark.asyncio
    async def test_appends_entry_to_log_panel(
        self, dashboard_app: DashboardApp
    ):
        """LogEmitted should append the log entry to the LogPanel."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            log_panel = screen.query_one("#log-panel", LogPanel)

            msg = LogEmitted(timestamp="14:30:00", level="info", message="Test log")
            dashboard_app.on_log_emitted(msg)

            assert len(log_panel._entries) == 1
            assert log_panel._entries[0].timestamp == "14:30:00"
            assert log_panel._entries[0].level == "info"
            assert log_panel._entries[0].message == "Test log"

    @pytest.mark.asyncio
    async def test_multiple_log_entries(
        self, dashboard_app: DashboardApp
    ):
        """Multiple LogEmitted messages should append in order."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            log_panel = screen.query_one("#log-panel", LogPanel)

            dashboard_app.on_log_emitted(
                LogEmitted(timestamp="14:30:00", level="info", message="First")
            )
            dashboard_app.on_log_emitted(
                LogEmitted(timestamp="14:30:01", level="warning", message="Second")
            )

            assert len(log_panel._entries) == 2
            assert log_panel._entries[0].message == "First"
            assert log_panel._entries[1].message == "Second"


class TestOnAnalysisComplete:
    """Tests for on_analysis_complete handler (Req 7.4, 2.8)."""

    @pytest.mark.asyncio
    async def test_updates_metrics_panel_with_result(
        self, dashboard_app: DashboardApp, sample_result: AnalysisResult
    ):
        """AnalysisComplete should update MetricsPanel with the final result."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            metrics_panel = screen.query_one("#metrics-panel", MetricsPanel)

            msg = AnalysisComplete(result=sample_result)
            dashboard_app.on_analysis_complete(msg)

            assert metrics_panel.score == 85
            assert metrics_panel.grade == "B"
            assert metrics_panel.risk_level == "medium"

    @pytest.mark.asyncio
    async def test_applies_highlight_class(
        self, dashboard_app: DashboardApp, sample_result: AnalysisResult
    ):
        """AnalysisComplete should apply highlight-complete class to MetricsPanel."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            metrics_panel = screen.query_one("#metrics-panel", MetricsPanel)

            msg = AnalysisComplete(result=sample_result)
            dashboard_app.on_analysis_complete(msg)

            assert metrics_panel.has_class("highlight-complete")

    @pytest.mark.asyncio
    async def test_updates_status_to_complete(
        self, dashboard_app: DashboardApp, sample_result: AnalysisResult
    ):
        """AnalysisComplete should set the header status to 'complete'."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            header = screen.query_one("#header-panel", HeaderPanel)

            msg = AnalysisComplete(result=sample_result)
            dashboard_app.on_analysis_complete(msg)

            status = header._statuses["analysis"]
            assert status.state == "complete"
            assert status.label == "complete"

    @pytest.mark.asyncio
    async def test_highlight_removed_after_timer(
        self, dashboard_app: DashboardApp, sample_result: AnalysisResult
    ):
        """Highlight class should be removed after the timer fires."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            metrics_panel = screen.query_one("#metrics-panel", MetricsPanel)

            msg = AnalysisComplete(result=sample_result)
            dashboard_app.on_analysis_complete(msg)

            assert metrics_panel.has_class("highlight-complete")

            # Advance time to trigger the timer callback (2 seconds + buffer)
            await pilot.pause(2.5)

            assert not metrics_panel.has_class("highlight-complete")


class TestOnAnalysisError:
    """Tests for on_analysis_error handler (Req 2.9, 10.4)."""

    @pytest.mark.asyncio
    async def test_updates_status_to_error(
        self, dashboard_app: DashboardApp
    ):
        """AnalysisError should set the header status to 'error' with source."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            header = screen.query_one("#header-panel", HeaderPanel)

            msg = AnalysisError(source="ai_engine", summary="API rate limit exceeded")
            dashboard_app.on_analysis_error(msg)

            status = header._statuses["analysis"]
            assert status.state == "error"
            assert status.label == "ai_engine"

    @pytest.mark.asyncio
    async def test_logs_error_to_log_panel(
        self, dashboard_app: DashboardApp
    ):
        """AnalysisError should log the error details to the LogPanel."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            screen = dashboard_app.screen
            log_panel = screen.query_one("#log-panel", LogPanel)

            msg = AnalysisError(source="timeout", summary="Request timed out")
            dashboard_app.on_analysis_error(msg)

            assert len(log_panel._entries) == 1
            entry = log_panel._entries[0]
            assert entry.level == "error"
            assert "timeout" in entry.message
            assert "Request timed out" in entry.message

    @pytest.mark.asyncio
    async def test_error_does_not_terminate_app(
        self, dashboard_app: DashboardApp
    ):
        """AnalysisError should not terminate the application (Req 10.4)."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            msg = AnalysisError(source="unknown", summary="Unexpected error")
            dashboard_app.on_analysis_error(msg)

            # App should still be running
            assert dashboard_app.is_running
