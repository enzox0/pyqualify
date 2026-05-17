"""CLI progress indicator for PyQualify analysis operations.

Provides a context-manager-based spinner that displays progress
during long-running async analysis operations, integrating with
click's terminal output.
"""

import sys
import threading
import time
from itertools import cycle
from types import TracebackType

import click


class ProgressIndicator:
    """A spinner-based progress indicator for CLI operations.

    Displays an animated spinner with a message using click.echo,
    updating at least once per second. Designed to be used as a
    context manager for clean setup and teardown.

    Usage:
        with ProgressIndicator("Analyzing..."):
            # long-running operation
            await run_analysis()
    """

    SPINNER_FRAMES: list[str] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Processing", update_interval: float = 0.1) -> None:
        """Initialize the progress indicator.

        Args:
            message: The message to display alongside the spinner.
            update_interval: How often to update the spinner frame in seconds.
                Defaults to 0.1s (10 updates/sec), well above the 1/sec minimum.
        """
        self._message = message
        self._update_interval = update_interval
        self._active = False
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "ProgressIndicator":
        """Start the progress indicator."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop the progress indicator and clean up the spinner line."""
        self.stop()

    def start(self) -> None:
        """Start the spinner in a background thread."""
        if self._active:
            return
        self._active = True
        self._thread = threading.Thread(
            target=self._run_spinner, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the spinner and clear the spinner line from the terminal."""
        if not self._active:
            return
        self._active = False
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        # Clear the spinner line
        click.echo("\r" + " " * (len(self._message) + 10) + "\r", nl=False, err=True)

    @property
    def is_active(self) -> bool:
        """Whether the spinner is currently running."""
        return self._active

    def _run_spinner(self) -> None:
        """Run the spinner animation loop in a background thread."""
        spinner = cycle(self.SPINNER_FRAMES)
        while self._active:
            frame = next(spinner)
            click.echo(f"\r  {frame} {self._message}", nl=False, err=True)
            time.sleep(self._update_interval)
