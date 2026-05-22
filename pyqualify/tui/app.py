"""DashboardApp - Main Textual application for the PyQualify TUI dashboard.

Implements the top-level Textual App with global key bindings for quit,
help, and panel focus switching. Pushes DashboardScreen on mount and
manages the analysis lifecycle.

Requirements: 6.2, 6.3, 6.5, 6.6, 1.1, 7.1, 7.2, 7.3, 7.4, 7.5, 2.8, 2.9, 8.4, 8.5, 10.1, 2.2, 2.3, 2.4, 2.5
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding

from pyqualify.container import Container, DependencyNotRegisteredError
from pyqualify.models import AnalysisMode
from pyqualify.tui.messages import (
    AnalysisComplete,
    AnalysisError,
    IssueDiscovered,
    LogEmitted,
    ProgressUpdate,
)
from pyqualify.tui.screens import DashboardScreen, ToolSelectionScreen
from pyqualify.tui.widgets import NavigationBar
from pyqualify.tui.widgets.header_panel import HeaderPanel
from pyqualify.tui.widgets.issues_table import IssuesTable
from pyqualify.tui.widgets.log_panel import LogPanel
from pyqualify.tui.widgets.metrics_panel import MetricsPanel


class _LogPanelHandler(logging.Handler):
    """A logging handler that routes log records into the TUI LogPanel.

    Bridges Python's standard logging system (used by PyqualifyLogger)
    to the TUI's LogPanel widget for real-time log display.
    """

    def __init__(self, app: DashboardApp) -> None:
        super().__init__()
        self._app = app

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record to the LogPanel via a LogEmitted message.

        Args:
            record: The log record from Python's logging system.
        """
        try:
            timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            level = record.levelname.lower()
            # Map Python log levels to our level names
            level_map = {"debug": "debug", "info": "info", "warning": "warning", "error": "error", "critical": "error"}
            level = level_map.get(level, "info")
            message = self.format(record) if self.formatter else record.getMessage()
            self._app.post_message(LogEmitted(timestamp=timestamp, level=level, message=message))
        except Exception:
            # Avoid recursion if posting fails
            pass


class DashboardApp(App[None]):
    """Main Textual application for the PyQualify TUI dashboard.

    Manages global key bindings, screen lifecycle, and panel focus.
    Accepts a DI container, optional analysis mode, and optional target
    for auto-starting analysis on launch.
    """

    CSS_PATH = "dashboard.tcss"

    ENABLE_COMMAND_PALETTE = False

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+c", "force_quit", "Force Quit", show=False),
        Binding("question_mark", "help", "Help"),
        Binding("1", "focus_metrics", "Metrics"),
        Binding("2", "focus_issues", "Issues"),
        Binding("3", "focus_logs", "Logs"),
    ]

    def __init__(
        self,
        container: Container,
        mode: AnalysisMode | None = None,
        target: str | None = None,
    ) -> None:
        """Initialize the DashboardApp.

        Args:
            container: The PyQualify DI container for resolving dependencies.
            mode: Optional analysis mode (web, code, or api) for auto-start.
            target: Optional target URL or path for auto-start analysis.
        """
        super().__init__()
        self._container = container
        self._mode = mode
        self._target = target
        self._runner_task = None
        self._runner = None
        self._log_handler: _LogPanelHandler | None = None
        # Rendering error recovery tracking (Req 10.1)
        self._render_error_count: int = 0
        self._first_render_error_time: float | None = None

    @property
    def container(self) -> Container:
        """Access the DI container."""
        return self._container

    @property
    def mode(self) -> AnalysisMode | None:
        """Access the analysis mode."""
        return self._mode

    @property
    def target(self) -> str | None:
        """Access the analysis target."""
        return self._target

    async def on_mount(self) -> None:
        """Push the DashboardScreen, wire DI dependencies, and auto-start if configured.

        Resolves ConfigManager, AIEngine, and analyzers from the DI container.
        Initializes status indicators based on current configuration state.
        Sets up AnalysisRunner with resolved dependencies.
        Registers a log handler to capture PyqualifyLogger output into LogPanel.

        Requirement 1.5: If terminal is below 80x24, do not render the
        multi-panel layout and display a message indicating minimum dimensions.
        Requirement 2.2: Green filled circle when AI engine is configured.
        Requirement 2.3: Yellow hollow circle when AI engine is not configured.
        Requirement 2.4: Green filled circle when analyzer is available.
        Requirement 2.5: Yellow hollow circle when no analyzer is available.
        Requirement 8.1: Launch TUI and render panel layout.
        Requirement 8.4: When both mode and target are provided, begin
        analysis automatically upon launch without additional user interaction.
        Requirement 8.5: When launched without a target, display idle state
        and await user-initiated analysis via keyboard shortcuts.
        """
        # Check terminal dimensions before rendering the dashboard (Req 1.5, 10.2)
        width = self.size.width
        height = self.size.height
        if width < 80 or height < 24:
            self.bell()
            self.notify(
                f"Terminal too small ({width}x{height}). "
                f"Minimum required: 80x24. Please resize your terminal.",
                severity="error",
                timeout=5,
            )
            self.exit(return_code=1)
            return

        self.push_screen(DashboardScreen())

        # ─── Show tool selection when no mode/target provided (Req 8.5) ──────
        if self._mode is None or self._target is None:
            async def _on_selection(result: tuple | None) -> None:
                if result is None:
                    return
                mode, target = result
                self._mode = mode
                self._target = target
                await self._start_analysis_after_selection()

            await self.push_screen(ToolSelectionScreen(), callback=_on_selection)

        # ─── Resolve dependencies from DI container ──────────────────────────
        from pyqualify.ai.engine import AIEngine
        from pyqualify.analyzers.api_analyzer import APIAnalyzer
        from pyqualify.analyzers.code_analyzer import CodeAnalyzer
        from pyqualify.analyzers.web_analyzer import WebAnalyzer
        from pyqualify.config.manager import ConfigManager
        from pyqualify.logging.logger import PyqualifyLogger
        from pyqualify.tui.runner import AnalysisRunner

        # Resolve ConfigManager to check configuration state
        config_manager: ConfigManager | None = None
        try:
            config_manager = self._container.resolve(ConfigManager)
        except DependencyNotRegisteredError:
            pass

        # Resolve AIEngine (may fail if not configured)
        ai_engine = None
        try:
            ai_engine = self._container.resolve(AIEngine)
        except (DependencyNotRegisteredError, Exception):
            pass

        # Resolve analyzers to check availability
        available_analyzers: list[str] = []
        analyzer_map = {
            "web": WebAnalyzer,
            "code": CodeAnalyzer,
            "api": APIAnalyzer,
        }
        for name, analyzer_cls in analyzer_map.items():
            try:
                self._container.resolve(analyzer_cls)
                available_analyzers.append(name)
            except (DependencyNotRegisteredError, Exception):
                pass

        # ─── Initialize status indicators (Req 2.2, 2.3, 2.4, 2.5) ─────────
        try:
            header = self.screen.query_one("#header-panel", HeaderPanel)

            # AI Engine status (Req 2.2, 2.3)
            if config_manager and config_manager.is_configured() and ai_engine is not None:
                header.update_status("ai_engine", "ready", "ready")
            else:
                header.update_status("ai_engine", "setup_needed", "setup needed")

            # Analyzer status (Req 2.4, 2.5)
            if self._mode and self._mode.value in available_analyzers:
                header.update_status("analyzer", "ready", f"{self._mode.value} analyzer")
            elif available_analyzers:
                header.update_status("analyzer", "ready", f"{available_analyzers[0]} analyzer")
            else:
                header.update_status("analyzer", "setup_needed", "no analyzer")

            # Analysis status starts as idle (Req 2.6)
            header.update_status("analysis", "idle", "idle")
        except Exception:
            pass

        # ─── Register log handler for PyqualifyLogger → LogPanel ─────────────
        self._log_handler: _LogPanelHandler | None = None
        try:
            # Get the root pyqualify logger and attach our TUI handler
            pyqualify_root_logger = logging.getLogger("pyqualify")
            self._log_handler = _LogPanelHandler(self)
            self._log_handler.setFormatter(
                logging.Formatter("%(name)s: %(message)s")
            )
            pyqualify_root_logger.addHandler(self._log_handler)
        except Exception:
            pass

        # ─── Set up AnalysisRunner with resolved dependencies ────────────────
        self._runner = AnalysisRunner(app=self, container=self._container)

        # ─── Auto-start analysis if mode and target are provided (Req 8.4) ───
        if self._mode is not None and self._target is not None:
            # Update status to running
            try:
                header = self.screen.query_one("#header-panel", HeaderPanel)
                header.update_status("analysis", "running", "analyzing")
            except Exception:
                pass

            self._runner_task = asyncio.create_task(
                self._runner.run(self._mode, self._target)
            )

    async def _start_analysis_after_selection(self) -> None:
        """Begin analysis after the user picks a mode and target from the
        ToolSelectionScreen.  Updates the header status and kicks off the
        AnalysisRunner task.
        """
        if self._mode is None or self._target is None:
            return

        # Update AI Engine and Analyzer status indicators now that mode is known
        try:
            from pyqualify.analyzers.api_analyzer import APIAnalyzer
            from pyqualify.analyzers.code_analyzer import CodeAnalyzer
            from pyqualify.analyzers.web_analyzer import WebAnalyzer
            from pyqualify.config.manager import ConfigManager
            from pyqualify.ai.engine import AIEngine

            header = self.screen.query_one("#header-panel", HeaderPanel)

            config_manager = self._container.resolve(ConfigManager)
            ai_engine = None
            try:
                ai_engine = self._container.resolve(AIEngine)
            except Exception:
                pass

            if config_manager.is_configured() and ai_engine is not None:
                header.update_status("ai_engine", "ready", "ready")
            else:
                header.update_status("ai_engine", "setup_needed", "setup needed")

            # Check if the selected analyzer is available
            analyzer_map = {"web": WebAnalyzer, "code": CodeAnalyzer, "api": APIAnalyzer}
            analyzer_cls = analyzer_map.get(self._mode.value)
            try:
                if analyzer_cls:
                    self._container.resolve(analyzer_cls)
                header.update_status("analyzer", "ready", f"{self._mode.value} analyzer")
            except Exception:
                header.update_status("analyzer", "setup_needed", "no analyzer")

            header.update_status("analysis", "running", "analyzing")
        except Exception:
            pass

        if self._runner is not None:
            self._runner_task = asyncio.create_task(
                self._runner.run(self._mode, self._target)
            )

    async def action_quit(self) -> None:
        """Stop any running analysis, restore terminal, and exit with code 0.

        Requirement 6.2: Stop running analysis, restore terminal to its
        original cursor and mode state, and exit with code 0.
        """
        # Cancel any running analysis task
        if self._runner_task is not None:
            self._runner_task.cancel()
            self._runner_task = None

        # Remove the log handler to prevent dangling references
        self._remove_log_handler()

        # Exit the app cleanly (Textual handles terminal restoration)
        self.exit(return_code=0)

    async def action_force_quit(self) -> None:
        """Cancel in-progress analysis and exit with code 130 on Ctrl+C.

        Requirement 10.3: When the user presses Ctrl+C, cancel any
        in-progress analysis, restore the terminal state, and exit
        with code 130.
        """
        # Cancel any running analysis task
        if self._runner_task is not None:
            self._runner_task.cancel()
            self._runner_task = None

        # Remove the log handler to prevent dangling references
        self._remove_log_handler()

        # Exit with code 130 (standard for SIGINT/Ctrl+C)
        self.exit(return_code=130)

    async def action_help(self) -> None:
        """Display the help modal overlay with all keyboard shortcuts.

        Requirement 6.5: Display a modal overlay listing all available
        keyboard shortcuts grouped by panel context with descriptions.
        """
        from pyqualify.tui.widgets.help_modal import HelpModal

        await self.push_screen(HelpModal())

    def action_focus_metrics(self) -> None:
        """Focus the MetricsPanel and update navigation context.

        Requirement 6.3: Move input focus to the metrics panel and
        visually highlight the focused panel's border using cyan.
        """
        try:
            metrics_panel = self.query_one("#metrics-panel")
            metrics_panel.focus()
            self._update_navigation_context("metrics")
        except Exception:
            pass

    def action_focus_issues(self) -> None:
        """Focus the IssuesTable and update navigation context.

        Requirement 6.3: Move input focus to the issues panel and
        visually highlight the focused panel's border using cyan.
        """
        try:
            issues_table = self.query_one("#issues-table")
            issues_table.focus()
            self._update_navigation_context("issues")
        except Exception:
            pass

    def action_focus_logs(self) -> None:
        """Focus the LogPanel and update navigation context.

        Requirement 6.3: Move input focus to the log panel and
        visually highlight the focused panel's border using cyan.
        """
        try:
            log_panel = self.query_one("#log-panel")
            log_panel.focus()
            self._update_navigation_context("logs")
        except Exception:
            pass

    def _update_navigation_context(self, panel_name: str) -> None:
        """Update the NavigationBar to show context-sensitive shortcuts.

        Requirement 6.4: When the focused panel changes, update displayed
        shortcuts to show only the shortcuts applicable to the newly focused
        panel in addition to global shortcuts.

        Args:
            panel_name: Identifier of the focused panel
                ("metrics", "issues", or "logs").
        """
        try:
            nav_bar = self.query_one("#navigation-bar", NavigationBar)
            nav_bar.update_context(panel_name)
        except Exception:
            pass

    def _remove_log_handler(self) -> None:
        """Remove the TUI log handler from the pyqualify logger.

        Called during shutdown to prevent dangling references and
        avoid emitting messages to a destroyed LogPanel.
        """
        if self._log_handler is not None:
            try:
                pyqualify_root_logger = logging.getLogger("pyqualify")
                pyqualify_root_logger.removeHandler(self._log_handler)
            except Exception:
                pass
            self._log_handler = None

    # ─── Unrecoverable Error Fallback (Req 10.5) ────────────────────────

    def _handle_exception(self, error: Exception) -> None:
        """Handle unrecoverable exceptions ensuring terminal state is restored.

        Requirement 10.5: On unrecoverable errors, restore terminal state
        (alternate screen buffer, cursor visibility, input mode) and exit
        with a non-zero exit code. The terminal must never be left in a
        corrupted state.

        Textual's base _handle_exception sets return_code=1 and triggers
        app shutdown (which restores terminal state in the run_async finally
        block). We override to additionally cancel any running analysis and
        log the error for diagnostics.

        Args:
            error: The unhandled exception.
        """
        # Cancel any running analysis task to prevent orphaned coroutines
        if self._runner_task is not None:
            self._runner_task.cancel()
            self._runner_task = None

        # Remove the log handler to prevent dangling references
        self._remove_log_handler()

        # Log the error for diagnostics (best-effort, may fail if app is broken)
        try:
            self.log.error(
                f"Unrecoverable error: {type(error).__name__}: {error}"
            )
        except Exception:
            pass

        # Delegate to Textual's built-in handler which:
        # 1. Sets _return_code = 1 (non-zero exit)
        # 2. Triggers _fatal_error() → _close_messages_no_wait()
        # 3. run_async's finally block calls _shutdown() to restore terminal
        super()._handle_exception(error)

    # ─── Event Handlers for Live Updates (Req 7.1-7.5, 2.8, 2.9) ────────

    def on_progress_update(self, message: ProgressUpdate) -> None:
        """Handle ProgressUpdate: update progress indicator in HeaderPanel.

        Updates the analysis status indicator with the current phase name
        and percentage. Keeps the spinner running state active.

        Requirement 7.3: Display progress indicator with phase name and
        percentage (0-100%) representing estimated completion.
        """
        try:
            header = self.screen.query_one("#header-panel", HeaderPanel)
            label = f"{message.phase} ({message.percent}%)"
            header.update_status("analysis", "running", label)
        except Exception:
            pass

    def on_issue_discovered(self, message: IssueDiscovered) -> None:
        """Handle IssueDiscovered: append issue to IssuesTable and update counts.

        Appends the newly discovered issue to the issues table and updates
        the issue counts in the MetricsPanel to reflect the new totals.

        Requirement 7.2: Append new issues to the Issues_Table within
        2 seconds of each issue being discovered.
        """
        try:
            issues_table = self.screen.query_one("#issues-table", IssuesTable)
            issues_table.append_issue(message.issue)
        except Exception:
            pass

        try:
            metrics_panel = self.screen.query_one("#metrics-panel", MetricsPanel)
            # Update issue counts by incrementing the appropriate severity
            severity_key = message.issue.severity.value
            counts = dict(metrics_panel.issue_counts)
            if severity_key in counts:
                counts[severity_key] += 1
            else:
                counts[severity_key] = 1
            metrics_panel.issue_counts = counts
        except Exception:
            pass

    def on_log_emitted(self, message: LogEmitted) -> None:
        """Handle LogEmitted: append entry to LogPanel.

        Appends the log message to the log panel for real-time display.

        Requirement 7.1: Display log messages within 500ms of emission.
        """
        try:
            log_panel = self.screen.query_one("#log-panel", LogPanel)
            log_panel.append_log(message.timestamp, message.level, message.message)
        except Exception:
            pass

    def on_analysis_complete(self, message: AnalysisComplete) -> None:
        """Handle AnalysisComplete: update metrics, apply highlight, set status.

        Updates the MetricsPanel with the final analysis result, applies a
        highlight effect lasting 2 seconds to signal completion, and
        transitions the status indicator to "complete".

        Requirement 7.4: Apply highlight effect on MetricsPanel lasting
        between 1 and 3 seconds to signal completion.
        Requirement 2.8: Transition to green checkmark "complete" within
        1 second of analysis finishing.
        """
        # Update MetricsPanel with final result
        try:
            metrics_panel = self.screen.query_one("#metrics-panel", MetricsPanel)
            metrics_panel.update_from_result(message.result)
            # Apply highlight effect class
            metrics_panel.add_class("highlight-complete")
            # Remove highlight after 2 seconds (within 1-3 second range per Req 7.4)
            self.set_timer(2.0, self._remove_metrics_highlight)
        except Exception:
            pass

        # Update status indicator to "complete" (Req 2.8)
        try:
            header = self.screen.query_one("#header-panel", HeaderPanel)
            header.update_status("analysis", "complete", "complete")
        except Exception:
            pass

    def _remove_metrics_highlight(self) -> None:
        """Remove the highlight-complete class from MetricsPanel after timeout."""
        try:
            metrics_panel = self.screen.query_one("#metrics-panel", MetricsPanel)
            metrics_panel.remove_class("highlight-complete")
        except Exception:
            pass

    def on_analysis_error(self, message: AnalysisError) -> None:
        """Handle AnalysisError: update status to error state, log error.

        Updates the status indicator to show the error state with the
        error source, and logs the error details to the LogPanel.

        Requirement 2.9: Transition to red cross symbol with error source label.
        Requirement 10.4: Display error category and summary in LogPanel
        without terminating the application.
        """
        # Update status indicator to error state (Req 2.9)
        try:
            header = self.screen.query_one("#header-panel", HeaderPanel)
            header.update_status("analysis", "error", message.source)
        except Exception:
            pass

        # Log the error to LogPanel (Req 10.4)
        try:
            log_panel = self.screen.query_one("#log-panel", LogPanel)
            timestamp = datetime.now().strftime("%H:%M:%S")
            log_panel.append_log(
                timestamp, "error", f"[{message.source}] {message.summary}"
            )
        except Exception:
            pass

    # ─── Rendering Error Recovery (Req 10.1) ─────────────────────────────

    def handle_render_error(self, error: Exception, widget=None) -> None:
        """Handle a rendering error with recovery logic.

        Logs the error to LogPanel, attempts to re-render the affected widget,
        and tracks consecutive errors. If 3 errors occur within 10 seconds,
        performs a graceful shutdown.

        Requirement 10.1: Log rendering errors, attempt re-render, and fall
        back to graceful shutdown if 3 consecutive errors occur within 10 seconds.

        Args:
            error: The exception that occurred during rendering.
            widget: The widget that failed to render (optional).
        """
        now = time.monotonic()

        # Reset counter if more than 10 seconds have passed since first error
        if (
            self._first_render_error_time is not None
            and now - self._first_render_error_time > 10.0
        ):
            self._render_error_count = 0
            self._first_render_error_time = None

        # Track the error
        if self._first_render_error_time is None:
            self._first_render_error_time = now
        self._render_error_count += 1

        # Log the error to LogPanel
        try:
            log_panel = self.screen.query_one("#log-panel", LogPanel)
            timestamp = datetime.now().strftime("%H:%M:%S")
            widget_name = type(widget).__name__ if widget else "unknown"
            log_panel.append_log(
                timestamp,
                "error",
                f"[render] {widget_name}: {error}",
            )
        except Exception:
            pass

        # Check if we've hit the threshold for graceful shutdown
        if self._render_error_count >= 3:
            self.exit(return_code=1)
            return

        # Attempt to re-render the affected widget
        if widget is not None:
            try:
                widget.refresh()
            except Exception:
                pass
