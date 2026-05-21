"""Unit tests for rendering error recovery (Task 8.3).

Tests cover:
- Error counter initialization
- Single error: logs to LogPanel and attempts re-render
- Counter reset after 10 seconds
- Graceful shutdown after 3 consecutive errors within 10 seconds

Requirements: 10.1
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, PropertyMock

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


def _patch_screen(dashboard_app, query_one_return=None, query_one_side_effect=None):
    """Patch the screen property on the DashboardApp class to return a mock screen.

    Returns a context manager that patches the 'screen' property at the class level
    to avoid triggering Textual's ScreenStackError.
    """
    mock_screen = MagicMock()
    if query_one_side_effect is not None:
        mock_screen.query_one = MagicMock(side_effect=query_one_side_effect)
    elif query_one_return is not None:
        mock_screen.query_one = MagicMock(return_value=query_one_return)
    else:
        mock_screen.query_one = MagicMock(side_effect=Exception("no panel"))

    return patch.object(
        type(dashboard_app), "screen", new_callable=PropertyMock, return_value=mock_screen
    )


class TestRenderErrorRecoveryInit:
    """Tests for render error tracking initialization."""

    def test_render_error_count_initialized_to_zero(self, dashboard_app):
        """Error counter should start at 0."""
        assert dashboard_app._render_error_count == 0

    def test_first_render_error_time_initialized_to_none(self, dashboard_app):
        """First error timestamp should start as None."""
        assert dashboard_app._first_render_error_time is None


class TestHandleRenderError:
    """Tests for handle_render_error method."""

    def test_increments_error_count(self, dashboard_app):
        """Each call to handle_render_error should increment the counter."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app):
            dashboard_app.handle_render_error(error)

        assert dashboard_app._render_error_count == 1

    def test_sets_first_error_time(self, dashboard_app):
        """First error should set the timestamp."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app):
            dashboard_app.handle_render_error(error)

        assert dashboard_app._first_render_error_time is not None

    def test_attempts_widget_refresh(self, dashboard_app):
        """Should call refresh() on the affected widget."""
        error = RuntimeError("render failed")
        mock_widget = MagicMock()

        with _patch_screen(dashboard_app):
            dashboard_app.handle_render_error(error, widget=mock_widget)

        mock_widget.refresh.assert_called_once()

    def test_no_crash_when_widget_is_none(self, dashboard_app):
        """Should not crash when widget is None."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app):
            # Should not raise
            dashboard_app.handle_render_error(error, widget=None)

        assert dashboard_app._render_error_count == 1

    def test_graceful_shutdown_on_three_errors_within_10_seconds(
        self, dashboard_app
    ):
        """Should call exit(return_code=1) after 3 errors within 10 seconds."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app), \
             patch.object(dashboard_app, "exit") as mock_exit:

            dashboard_app.handle_render_error(error)
            dashboard_app.handle_render_error(error)
            dashboard_app.handle_render_error(error)

            mock_exit.assert_called_once_with(return_code=1)

    def test_no_shutdown_on_two_errors(self, dashboard_app):
        """Should NOT call exit after only 2 errors."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app), \
             patch.object(dashboard_app, "exit") as mock_exit:

            dashboard_app.handle_render_error(error)
            dashboard_app.handle_render_error(error)

            mock_exit.assert_not_called()

    def test_counter_resets_after_10_seconds(self, dashboard_app):
        """Counter should reset if more than 10 seconds pass since first error."""
        error = RuntimeError("render failed")

        with _patch_screen(dashboard_app), \
             patch.object(dashboard_app, "exit") as mock_exit:

            # Simulate first two errors
            dashboard_app.handle_render_error(error)
            dashboard_app.handle_render_error(error)

            # Simulate time passing beyond 10 seconds
            dashboard_app._first_render_error_time = time.monotonic() - 11.0

            # Third error should reset the counter (not trigger shutdown)
            dashboard_app.handle_render_error(error)

            mock_exit.assert_not_called()
            # Counter should be 1 (reset + this new error)
            assert dashboard_app._render_error_count == 1

    def test_logs_error_to_log_panel(self, dashboard_app):
        """Should log the rendering error to LogPanel."""
        error = RuntimeError("widget broke")
        mock_widget = MagicMock()
        mock_widget.__class__.__name__ = "MetricsPanel"
        mock_log_panel = MagicMock()

        with _patch_screen(dashboard_app, query_one_return=mock_log_panel):
            dashboard_app.handle_render_error(error, widget=mock_widget)

        mock_log_panel.append_log.assert_called_once()
        call_args = mock_log_panel.append_log.call_args
        assert call_args[0][1] == "error"
        assert "render" in call_args[0][2]
        assert "widget broke" in call_args[0][2]

    def test_does_not_refresh_widget_after_shutdown_triggered(
        self, dashboard_app
    ):
        """After triggering shutdown, should not attempt widget refresh."""
        error = RuntimeError("render failed")
        mock_widget = MagicMock()

        with _patch_screen(dashboard_app), \
             patch.object(dashboard_app, "exit"):

            # First two errors - widget refresh should be called
            dashboard_app.handle_render_error(error, widget=mock_widget)
            dashboard_app.handle_render_error(error, widget=mock_widget)
            assert mock_widget.refresh.call_count == 2

            # Third error triggers shutdown - no refresh
            mock_widget.refresh.reset_mock()
            dashboard_app.handle_render_error(error, widget=mock_widget)
            mock_widget.refresh.assert_not_called()
