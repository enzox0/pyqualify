"""AnalysisRunner - Orchestrates analysis execution and emits progress events.

Resolves the appropriate analyzer from the DI container based on the
analysis mode, runs the analysis, and emits Textual messages for live
TUI updates including progress, issues, logs, completion, and errors.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pyqualify.ai.engine import AIEngine
from pyqualify.analyzers.api_analyzer import APIAnalyzer
from pyqualify.analyzers.code_analyzer import CodeAnalyzer
from pyqualify.analyzers.web_analyzer import WebAnalyzer
from pyqualify.config.manager import ConfigManager
from pyqualify.container import Container
from pyqualify.models import AnalysisConfig, AnalysisMode, AnalysisResult
from pyqualify.tui.messages import (
    AnalysisComplete,
    AnalysisError,
    IssueDiscovered,
    LogEmitted,
    ProgressUpdate,
)

if TYPE_CHECKING:
    from pyqualify.tui.app import DashboardApp

# Stall detection threshold in seconds
_STALL_TIMEOUT_SECONDS = 30


class AnalysisRunner:
    """Orchestrates analysis execution and emits progress events to the TUI.

    Resolves the appropriate analyzer from the container based on the
    analysis mode, runs the analyzer, and posts Textual messages to the
    app for live dashboard updates.
    """

    def __init__(self, app: DashboardApp, container: Container) -> None:
        """Initialize the AnalysisRunner.

        Args:
            app: The DashboardApp instance for posting messages.
            container: The DI container for resolving analyzers and services.
        """
        self._app = app
        self._container = container
        self._last_progress_time: float = 0.0
        self._stall_task: asyncio.Task[None] | None = None
        self._is_running: bool = False

    async def run(self, mode: AnalysisMode, target: str) -> AnalysisResult:
        """Run analysis and emit progress events to the TUI.

        Resolves the analyzer for the given mode, executes analysis,
        and emits messages for progress, issues, logs, completion, or errors.

        Args:
            mode: The analysis mode (web, code, or api).
            target: The analysis target (URL or file path).

        Returns:
            The complete AnalysisResult on success.

        Raises:
            Exception: Re-raises any unhandled exception after emitting
                AnalysisError to the app.
        """
        self._is_running = True
        self._last_progress_time = asyncio.get_event_loop().time()

        # Start stall detection
        self._stall_task = asyncio.create_task(self._stall_detector())

        try:
            # Emit initial progress
            self._emit_progress("Initializing", 0)
            self._emit_log("info", f"Starting {mode.value} analysis of {target}")

            # Resolve analyzer based on mode
            analyzer = self._resolve_analyzer(mode)
            self._emit_progress("Resolving dependencies", 5)
            self._emit_log("info", f"Resolved {mode.value} analyzer")

            # Resolve config
            config = self._resolve_analysis_config()
            self._emit_progress("Configuring", 10)

            # Run the analysis
            self._emit_progress("Analyzing", 15)
            self._emit_log("info", "Analysis started")

            result = await analyzer.analyze(target, config)

            # Emit discovered issues
            self._emit_progress("Processing results", 80)
            for issue in result.issues:
                self._app.post_message(IssueDiscovered(issue=issue))

            # Emit completion
            self._emit_progress("Complete", 100)
            self._emit_log("info", f"Analysis complete: {result.summary}")
            self._app.post_message(AnalysisComplete(result=result))

            return result

        except asyncio.CancelledError:
            self._emit_log("warning", "Analysis was cancelled")
            self._app.post_message(
                AnalysisError(source="cancelled", summary="Analysis was cancelled by user")
            )
            raise

        except Exception as exc:
            error_source = self._classify_error_source(exc, mode)
            summary = str(exc)[:200] if str(exc) else type(exc).__name__
            self._emit_log("error", f"Analysis failed: {summary}")
            self._app.post_message(
                AnalysisError(source=error_source, summary=summary)
            )
            raise

        finally:
            self._is_running = False
            if self._stall_task is not None and not self._stall_task.done():
                self._stall_task.cancel()
                try:
                    await self._stall_task
                except asyncio.CancelledError:
                    pass
                self._stall_task = None

    def _resolve_analyzer(self, mode: AnalysisMode) -> object:
        """Resolve the appropriate analyzer from the container.

        Args:
            mode: The analysis mode determining which analyzer to resolve.

        Returns:
            The resolved analyzer instance.
        """
        analyzer_map = {
            AnalysisMode.WEB: WebAnalyzer,
            AnalysisMode.CODE: CodeAnalyzer,
            AnalysisMode.API: APIAnalyzer,
        }
        analyzer_class = analyzer_map[mode]
        return self._container.resolve(analyzer_class)

    def _resolve_analysis_config(self) -> AnalysisConfig:
        """Resolve analysis configuration from the container.

        Returns:
            An AnalysisConfig instance with settings from ConfigManager.
        """
        try:
            config_manager = self._container.resolve(ConfigManager)
            timeout = int(config_manager.get("timeout", "30"))
            max_links = int(config_manager.get("max_links", "500"))
            rate_limit_burst = int(config_manager.get("rate_limit_burst", "50"))
            rate_limit_window = int(config_manager.get("rate_limit_window", "10"))
            return AnalysisConfig(
                timeout=timeout,
                max_links=max_links,
                rate_limit_burst=rate_limit_burst,
                rate_limit_window=rate_limit_window,
            )
        except Exception:
            # Fall back to defaults if config resolution fails
            return AnalysisConfig()

    def _emit_progress(self, phase: str, percent: int) -> None:
        """Emit a ProgressUpdate message and reset the stall timer.

        Args:
            phase: The current analysis phase name.
            percent: Estimated completion percentage (0-100).
        """
        self._last_progress_time = asyncio.get_event_loop().time()
        self._app.post_message(ProgressUpdate(phase=phase, percent=percent))

    def _emit_log(self, level: str, message: str) -> None:
        """Emit a LogEmitted message with the current timestamp.

        Args:
            level: Log level (debug, info, warning, error).
            message: The log message text.
        """
        timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        self._app.post_message(LogEmitted(timestamp=timestamp, level=level, message=message))

    async def _stall_detector(self) -> None:
        """Monitor for stalled analysis (no progress for 30 seconds).

        Runs as a background task and emits a ProgressUpdate with a
        stall indication if no progress updates occur within the threshold.
        """
        while self._is_running:
            await asyncio.sleep(1.0)
            if not self._is_running:
                break
            elapsed = asyncio.get_event_loop().time() - self._last_progress_time
            if elapsed >= _STALL_TIMEOUT_SECONDS:
                # Emit a stall-indicating progress update
                self._app.post_message(
                    ProgressUpdate(phase="Stalled", percent=-1)
                )
                self._emit_log(
                    "warning",
                    f"No progress updates for {_STALL_TIMEOUT_SECONDS} seconds",
                )
                # Reset timer to avoid spamming stall messages
                self._last_progress_time = asyncio.get_event_loop().time()

    def _classify_error_source(self, exc: Exception, mode: AnalysisMode) -> str:
        """Classify the error source for the AnalysisError message.

        Args:
            exc: The exception that occurred.
            mode: The analysis mode that was running.

        Returns:
            A string identifying the error source:
            "ai_engine", "analyzer", "timeout", or "unknown".
        """
        exc_type = type(exc).__name__.lower()
        exc_msg = str(exc).lower()

        if "timeout" in exc_type or "timeout" in exc_msg:
            return "timeout"
        if "ai" in exc_type or "openai" in exc_msg or "anthropic" in exc_msg:
            return "ai_engine"
        if "api" in exc_msg or "rate" in exc_msg or "limit" in exc_msg:
            return "ai_engine"
        if "analyzer" in exc_type or mode.value in exc_msg:
            return "analyzer"
        return "unknown"
