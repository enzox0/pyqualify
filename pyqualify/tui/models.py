"""TUI-specific data models for the PyQualify dashboard."""

from dataclasses import dataclass


@dataclass
class StatusState:
    """Represents the state of a single status indicator.

    Used by the HeaderPanel to display component health at a glance.
    """

    component: str
    """Component identifier: "ai_engine", "analyzer", or "analysis"."""

    state: str
    """Current state: "ready", "setup_needed", "idle", "running", "complete", or "error"."""

    label: str
    """Human-readable label displayed alongside the status symbol."""

    error_source: str | None = None
    """For error state: "ai_engine", "analyzer", "timeout", or "unknown"."""


@dataclass
class LogEntry:
    """A single log entry for the Log Panel.

    Represents one line of output in the live-scrolling log feed.
    """

    timestamp: str
    """Timestamp in HH:MM:SS format."""

    level: str
    """Log level: "debug", "info", "warning", or "error"."""

    message: str
    """The log message text."""


@dataclass
class ProgressState:
    """Tracks analysis progress for live updates.

    Used by the HeaderPanel and progress indicator to show current
    analysis phase and estimated completion.
    """

    phase: str
    """Current analysis phase name (e.g., "scanning", "enriching")."""

    percent: int
    """Estimated completion percentage, 0-100."""

    is_stalled: bool = False
    """True if no progress updates received for 30+ seconds."""
