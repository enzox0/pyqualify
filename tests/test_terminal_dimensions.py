"""Unit tests for terminal dimension validation (Task 8.1).

Tests cover:
- App exits with non-zero code when terminal is below 80x24
- App renders normally when terminal meets minimum dimensions
- DashboardScreen does not push when terminal is too small

Requirements: 1.5, 10.2
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from pyqualify.container import Container
from pyqualify.tui.app import DashboardApp
from pyqualify.tui.screens import DashboardScreen


@pytest.fixture
def mock_container():
    """Create a mock Container for DashboardApp."""
    return MagicMock(spec=Container)


class TestTerminalDimensionValidation:
    """Tests for terminal dimension validation on app mount (Req 1.5, 10.2)."""

    @pytest.mark.asyncio
    async def test_exits_with_code_1_when_width_too_small(self, mock_container):
        """App should exit with return_code=1 when terminal width < 80."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(60, 30)) as pilot:
            await pilot.pause(0.5)
            # App should have exited
            assert app.return_code == 1

    @pytest.mark.asyncio
    async def test_exits_with_code_1_when_height_too_small(self, mock_container):
        """App should exit with return_code=1 when terminal height < 24."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(100, 20)) as pilot:
            await pilot.pause(0.5)
            assert app.return_code == 1

    @pytest.mark.asyncio
    async def test_exits_with_code_1_when_both_dimensions_too_small(
        self, mock_container
    ):
        """App should exit with return_code=1 when both width and height are below minimum."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(40, 10)) as pilot:
            await pilot.pause(0.5)
            assert app.return_code == 1

    @pytest.mark.asyncio
    async def test_renders_normally_at_minimum_dimensions(self, mock_container):
        """App should render the dashboard when terminal is exactly 80x24."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause(0.5)
            # App should still be running (not exited)
            assert app.is_running
            # DashboardScreen should be the active screen
            assert isinstance(app.screen, DashboardScreen)

    @pytest.mark.asyncio
    async def test_renders_normally_above_minimum_dimensions(self, mock_container):
        """App should render the dashboard when terminal exceeds 80x24."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause(0.5)
            assert app.is_running
            assert isinstance(app.screen, DashboardScreen)

    @pytest.mark.asyncio
    async def test_does_not_push_dashboard_screen_when_too_small(self, mock_container):
        """When terminal is too small, DashboardScreen should NOT be pushed."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(50, 15)) as pilot:
            await pilot.pause(0.5)
            # The screen should NOT be a DashboardScreen
            assert not isinstance(app.screen, DashboardScreen)

    @pytest.mark.asyncio
    async def test_boundary_width_79_exits(self, mock_container):
        """Width of 79 (one below minimum) should trigger exit."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(79, 24)) as pilot:
            await pilot.pause(0.5)
            assert app.return_code == 1

    @pytest.mark.asyncio
    async def test_boundary_height_23_exits(self, mock_container):
        """Height of 23 (one below minimum) should trigger exit."""
        app = DashboardApp(container=mock_container)
        async with app.run_test(size=(80, 23)) as pilot:
            await pilot.pause(0.5)
            assert app.return_code == 1
