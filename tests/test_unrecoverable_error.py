"""Unit tests for unrecoverable error fallback (Task 8.5).

Tests cover:
- _handle_exception cancels running analysis task
- _handle_exception results in non-zero exit code
- _handle_exception delegates to Textual's base handler for terminal restoration
- Terminal is never left in a corrupted state on unhandled exceptions

Requirements: 10.5
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from pyqualify.container import Container
from pyqualify.tui.app import DashboardApp


@pytest.fixture
def mock_container():
    """Create a mock Container for DashboardApp."""
    return MagicMock(spec=Container)


@pytest.fixture
def dashboard_app(mock_container):
    """Create a DashboardApp instance for testing."""
    return DashboardApp(container=mock_container)


class TestUnrecoverableErrorFallback:
    """Tests for _handle_exception (Req 10.5)."""

    def test_handle_exception_cancels_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should cancel any running analysis task."""
        # Simulate a running analysis task
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        dashboard_app._runner_task = mock_task

        error = RuntimeError("Unrecoverable failure")

        # Patch the super()._handle_exception to prevent actual shutdown
        with patch.object(
            DashboardApp.__mro__[1], "_handle_exception"
        ):
            dashboard_app._handle_exception(error)

        mock_task.cancel.assert_called_once()
        assert dashboard_app._runner_task is None

    def test_handle_exception_without_runner_task(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should work even when no analysis is running."""
        assert dashboard_app._runner_task is None

        error = ValueError("Unexpected error")

        # Patch the super()._handle_exception to prevent actual shutdown
        with patch.object(
            DashboardApp.__mro__[1], "_handle_exception"
        ):
            dashboard_app._handle_exception(error)

        # Should not raise, runner_task remains None
        assert dashboard_app._runner_task is None

    def test_handle_exception_calls_super(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should delegate to Textual's base handler."""
        error = RuntimeError("Fatal error")

        # Patch the parent class _handle_exception to verify it's called
        with patch.object(
            DashboardApp.__mro__[1], "_handle_exception"
        ) as mock_super:
            dashboard_app._handle_exception(error)

        mock_super.assert_called_once_with(error)

    def test_handle_exception_sets_nonzero_return_code(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should result in non-zero return code via super."""
        error = RuntimeError("Something went terribly wrong")

        # Don't patch super - let it actually set the return code
        # But patch _fatal_error to prevent full shutdown side effects
        with patch.object(dashboard_app, "_fatal_error"):
            dashboard_app._handle_exception(error)

        assert dashboard_app._return_code == 1

    def test_handle_exception_stores_exception_for_reraise(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should store the exception for test re-raise."""
        error = RuntimeError("Fatal error")

        # Let super run but patch _fatal_error to prevent shutdown
        with patch.object(dashboard_app, "_fatal_error"):
            dashboard_app._handle_exception(error)

        # Textual stores the exception for re-raising in test mode
        assert dashboard_app._exception is error

    def test_handle_exception_logs_error_best_effort(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should attempt to log the error."""
        error = RuntimeError("Critical failure")

        from unittest.mock import PropertyMock

        mock_log = MagicMock()
        with patch.object(type(dashboard_app), "log", new_callable=PropertyMock, return_value=mock_log):
            with patch.object(dashboard_app, "_fatal_error"):
                dashboard_app._handle_exception(error)

        mock_log.error.assert_called_once_with(
            "Unrecoverable error: RuntimeError: Critical failure"
        )

    def test_handle_exception_survives_log_failure(
        self, dashboard_app: DashboardApp
    ):
        """_handle_exception should not fail if logging raises."""
        error = RuntimeError("Critical failure")

        from unittest.mock import PropertyMock

        # Make log.error raise to simulate broken logging
        mock_log = MagicMock()
        mock_log.error.side_effect = Exception("Logging broken")

        with patch.object(type(dashboard_app), "log", new_callable=PropertyMock, return_value=mock_log):
            with patch.object(dashboard_app, "_fatal_error"):
                # Should not raise despite logging failure
                dashboard_app._handle_exception(error)

        # Should still set return code
        assert dashboard_app._return_code == 1
