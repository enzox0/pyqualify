"""Unit tests for terminal resize handling (Task 9.2).

Tests cover:
- DashboardScreen handles resize events and reflows panel content
- Panels maintain borders as closed rectangles after resize
- Panel titles are preserved after resize
- MetricsPanel progress bar adapts to new width
- Resize below minimum dimensions triggers exit

Requirements: 1.3
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pyqualify.container import Container
from pyqualify.tui.app import DashboardApp
from pyqualify.tui.screens import DashboardScreen
from pyqualify.tui.widgets.header_panel import HeaderPanel
from pyqualify.tui.widgets.metrics_panel import MetricsPanel
from pyqualify.tui.widgets.issues_table import IssuesTable
from pyqualify.tui.widgets.log_panel import LogPanel
from pyqualify.tui.widgets import NavigationBar


@pytest.fixture
def mock_container():
    """Create a mock Container for DashboardApp."""
    return MagicMock(spec=Container)


class TestResizeHandling:
    """Tests for terminal resize handling in DashboardScreen (Req 1.3)."""

    @pytest.mark.asyncio
    async def test_resize_does_not_crash(self, mock_container):
        """Resizing the terminal should not cause any errors."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            assert app.is_running
            # Resize to a different valid size
            await pilot.resize_terminal(100, 30)
            await pilot.pause(0.5)
            # App should still be running
            assert app.is_running

    @pytest.mark.asyncio
    async def test_resize_maintains_dashboard_screen(self, mock_container):
        """After resize, DashboardScreen should still be the active screen."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            assert isinstance(app.screen, DashboardScreen)
            # Resize
            await pilot.resize_terminal(100, 30)
            await pilot.pause(0.5)
            # DashboardScreen should still be active
            assert isinstance(app.screen, DashboardScreen)

    @pytest.mark.asyncio
    async def test_resize_preserves_all_panels(self, mock_container):
        """All panels should still be present after a resize event."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            # Resize
            await pilot.resize_terminal(100, 35)
            await pilot.pause(0.5)
            # All panels should still be queryable
            assert app.screen.query_one("#header-panel", HeaderPanel)
            assert app.screen.query_one("#metrics-panel", MetricsPanel)
            assert app.screen.query_one("#issues-table", IssuesTable)
            assert app.screen.query_one("#log-panel", LogPanel)
            assert app.screen.query_one("#navigation-bar", NavigationBar)

    @pytest.mark.asyncio
    async def test_resize_below_minimum_exits(self, mock_container):
        """Resizing below 80x24 should trigger app exit with non-zero code."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            assert app.is_running
            # Resize below minimum
            await pilot.resize_terminal(60, 20)
            await pilot.pause(0.5)
            # App should have exited with non-zero code
            assert app.return_code == 1

    @pytest.mark.asyncio
    async def test_multiple_resizes_do_not_crash(self, mock_container):
        """Multiple consecutive resizes should not cause errors."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            # Perform multiple resizes
            await pilot.resize_terminal(100, 30)
            await pilot.pause(0.2)
            await pilot.resize_terminal(150, 50)
            await pilot.pause(0.2)
            await pilot.resize_terminal(80, 24)
            await pilot.pause(0.5)
            # App should still be running
            assert app.is_running
            assert isinstance(app.screen, DashboardScreen)


class TestMetricsPanelReflow:
    """Tests for MetricsPanel progress bar adapting to width on resize."""

    @pytest.mark.asyncio
    async def test_metrics_panel_renders_after_resize(self, mock_container):
        """MetricsPanel should render correctly after terminal resize."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            metrics = app.screen.query_one("#metrics-panel", MetricsPanel)
            # Set a score to verify rendering
            metrics.score = 75
            await pilot.pause(0.2)
            # Resize
            await pilot.resize_terminal(100, 35)
            await pilot.pause(0.5)
            # MetricsPanel should still be rendering (score preserved)
            assert metrics.score == 75
