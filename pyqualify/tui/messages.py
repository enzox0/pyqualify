"""Textual Message subclasses for TUI event communication.

These messages are emitted by the AnalysisRunner and consumed by
DashboardApp event handlers to drive live UI updates.
"""

from textual.message import Message

from pyqualify.models import AnalysisResult, Issue


class ProgressUpdate(Message):
    """Emitted when analysis progress changes."""

    def __init__(self, phase: str, percent: int) -> None:
        super().__init__()
        self.phase = phase
        self.percent = percent


class IssueDiscovered(Message):
    """Emitted when a new issue is found during analysis."""

    def __init__(self, issue: Issue) -> None:
        super().__init__()
        self.issue = issue


class LogEmitted(Message):
    """Emitted when a log message is produced."""

    def __init__(self, timestamp: str, level: str, message: str) -> None:
        super().__init__()
        self.timestamp = timestamp
        self.level = level
        self.message = message


class AnalysisComplete(Message):
    """Emitted when analysis finishes successfully."""

    def __init__(self, result: AnalysisResult) -> None:
        super().__init__()
        self.result = result


class AnalysisError(Message):
    """Emitted when analysis encounters an error."""

    def __init__(self, source: str, summary: str) -> None:
        super().__init__()
        self.source = source
        self.summary = summary
