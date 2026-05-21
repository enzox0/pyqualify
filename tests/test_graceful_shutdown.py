"""Unit tests for Ctrl+C and graceful shutdown handling (Task 8.2).

Tests cover:
- Ctrl+C (action_force_quit): cancels in-progress analysis, exits with code 130
- Quit action (q): stops analysis, exits with code 0

Requirements: 10.3, 6.2
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from pyqualify.container import Container
from pyqualify.models import AnalysisMode
from pyqualify.tui.app import DashboardApp


@pytest.fixture
def mock_container():
    """Create a mock Container for DashboardApp."""
    return MagicMock(spec=Container)


@pytest.fixture
def dashboard_app(mock_container):
    """Create a DashboardApp instance for testing."""
    return DashboardApp(container=mock_container)


class TestCtrlCForceQuit:
    """Tests for Ctrl+C / action_force_quit (Req 10.3)."""

    def test_ctrl_c_binding_exists(self, dashboard_app: DashboardApp):
        """DashboardApp should have a ctrl+c binding mapped to force_quit."""
        binding_keys = [b.key for b in DashboardApp.BINDINGS]
        assert "ctrl+c" in binding_keys

        # Find the ctrl+c binding and verify it maps to force_quit
        for b in DashboardApp.BINDINGS:
            if b.key == "ctrl+c":
                assert b.action == "force_quit"
                assert b.show is False
                break

    def test_command_palette_disabled(self):
        """ENABLE_COMMAND_PALETTE should be False to allow ctrl+c binding."""
        assert DashboardApp.ENABLE_COMMAND_PALETTE is False

    @pytest.mark.asyncio
    async def test_force_quit_exits_with_code_130(
        self, dashboard_app: DashboardApp
    ):
        """action_force_quit should exit the app with return code 130."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            await dashboard_app.action_force_quit()

            assert dashboard_app.return_code == 130

    @pytest.mark.asyncio
    async def test_force_quit_cancels_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """action_force_quit should cancel the runner task if one is running."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            # Simulate a running analysis task
            mock_task = MagicMock()
            mock_task.cancel = MagicMock()
            dashboard_app._runner_task = mock_task

            await dashboard_app.action_force_quit()

            mock_task.cancel.assert_called_once()
            assert dashboard_app._runner_task is None

    @pytest.mark.asyncio
    async def test_force_quit_without_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """action_force_quit should work even when no analysis is running."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            # Ensure no runner task is set
            assert dashboard_app._runner_task is None

            await dashboard_app.action_force_quit()

            assert dashboard_app.return_code == 130


class TestQuitAction:
    """Tests for quit action (q key) (Req 6.2)."""

    def test_quit_binding_exists(self, dashboard_app: DashboardApp):
        """DashboardApp should have a q binding mapped to quit."""
        binding_keys = [b.key for b in DashboardApp.BINDINGS]
        assert "q" in binding_keys

    @pytest.mark.asyncio
    async def test_quit_exits_with_code_0(
        self, dashboard_app: DashboardApp
    ):
        """action_quit should exit the app with return code 0."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            await dashboard_app.action_quit()

            assert dashboard_app.return_code == 0

    @pytest.mark.asyncio
    async def test_quit_cancels_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """action_quit should cancel the runner task if one is running."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            # Simulate a running analysis task
            mock_task = MagicMock()
            mock_task.cancel = MagicMock()
            dashboard_app._runner_task = mock_task

            await dashboard_app.action_quit()

            mock_task.cancel.assert_called_once()
            assert dashboard_app._runner_task is None

    @pytest.mark.asyncio
    async def test_quit_without_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """action_quit should work even when no analysis is running."""
        async with dashboard_app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(0.5)

            assert dashboard_app._runner_task is None

            await dashboard_app.action_quit()

            assert dashboard_app.return_code == 0
