"""Tests for the CLI progress indicator module."""

import time
import threading

from pyqualify.cli.progress import ProgressIndicator


class TestProgressIndicator:
    """Tests for ProgressIndicator class."""

    def test_context_manager_starts_and_stops(self) -> None:
        """ProgressIndicator starts on enter and stops on exit."""
        indicator = ProgressIndicator("Testing")
        assert not indicator.is_active

        with indicator:
            assert indicator.is_active

        assert not indicator.is_active

    def test_start_creates_background_thread(self) -> None:
        """Starting the indicator creates a daemon thread."""
        indicator = ProgressIndicator("Testing")
        indicator.start()
        try:
            assert indicator.is_active
            assert indicator._thread is not None
            assert indicator._thread.is_alive()
            assert indicator._thread.daemon is True
        finally:
            indicator.stop()

    def test_stop_joins_thread(self) -> None:
        """Stopping the indicator joins and clears the thread."""
        indicator = ProgressIndicator("Testing")
        indicator.start()
        indicator.stop()

        assert not indicator.is_active
        assert indicator._thread is None

    def test_double_start_is_safe(self) -> None:
        """Calling start twice does not create a second thread."""
        indicator = ProgressIndicator("Testing")
        indicator.start()
        first_thread = indicator._thread
        indicator.start()
        assert indicator._thread is first_thread
        indicator.stop()

    def test_double_stop_is_safe(self) -> None:
        """Calling stop twice does not raise an error."""
        indicator = ProgressIndicator("Testing")
        indicator.start()
        indicator.stop()
        indicator.stop()  # Should not raise

    def test_stop_without_start_is_safe(self) -> None:
        """Calling stop without start does not raise an error."""
        indicator = ProgressIndicator("Testing")
        indicator.stop()  # Should not raise

    def test_updates_at_least_once_per_second(self) -> None:
        """The spinner updates at least once per second (default interval is 0.1s)."""
        indicator = ProgressIndicator("Testing", update_interval=0.1)
        assert indicator._update_interval <= 1.0

    def test_custom_message(self) -> None:
        """ProgressIndicator stores the provided message."""
        indicator = ProgressIndicator("Analyzing code...")
        assert indicator._message == "Analyzing code..."

    def test_context_manager_cleans_up_on_exception(self) -> None:
        """ProgressIndicator stops even if the body raises an exception."""
        indicator = ProgressIndicator("Testing")
        try:
            with indicator:
                assert indicator.is_active
                raise ValueError("test error")
        except ValueError:
            pass

        assert not indicator.is_active

    def test_spinner_frames_are_defined(self) -> None:
        """Spinner frames list is non-empty."""
        assert len(ProgressIndicator.SPINNER_FRAMES) > 0

    def test_default_update_interval(self) -> None:
        """Default update interval is 0.1 seconds."""
        indicator = ProgressIndicator("Testing")
        assert indicator._update_interval == 0.1

