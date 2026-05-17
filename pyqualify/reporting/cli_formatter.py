"""CLI output formatter for PyQualify analysis results."""

import sys
import threading
import time
from itertools import cycle

import click

from pyqualify.models import AnalysisResult, Issue, Severity


class CLIFormatter:
    """Formats analysis results for terminal display.

    Implements ReportGeneratorProtocol for CLI output with color-coded
    severity levels consistent with the PyQualify banner theme:

      cyan/bold     — primary brand accent, recommendations
      bright_blue   — subtitles
      magenta       — author/brand accent
      bright_black  — muted labels, separators, metadata
      green         — success, passing scores
      yellow        — warnings, medium severity
      red/bright_red — errors, critical/high severity
      blue          — low severity
      white/bold    — section headers
    """

    SEVERITY_COLORS: dict[str, str] = {
        "critical": "red",
        "high":     "bright_red",
        "medium":   "yellow",
        "low":      "blue",
        "info":     "bright_black",
    }

    SEVERITY_ICONS: dict[str, str] = {
        "critical": "✖",
        "high":     "●",
        "medium":   "◆",
        "low":      "◇",
        "info":     "·",
    }

    SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

    SPINNER_FRAMES: list[str] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self) -> None:
        self._spinner_active: bool = False
        self._spinner_thread: threading.Thread | None = None

    def generate_cli_output(self, result: AnalysisResult, use_color: bool = True) -> None:
        """Display results in the terminal with color coding.

        Args:
            result: The complete analysis result to display.
            use_color: Whether to use color-coded output. Falls back to
                plain text with severity prefixes when False.
        """
        self._display_summary(result, use_color)
        self._display_issues(result.issues, use_color)

    def generate_html_report(self, result: AnalysisResult, output_path: str) -> None:
        """Generate HTML report. Delegates to HTMLDashboardGenerator.

        Raises:
            NotImplementedError: CLI formatter does not generate HTML reports.
        """
        raise NotImplementedError(
            "CLIFormatter does not support HTML report generation. "
            "Use HTMLDashboardGenerator instead."
        )

    # ── Summary block ─────────────────────────────────────────────────────────

    def _display_summary(self, result: AnalysisResult, use_color: bool) -> None:
        """Display the summary block with Score, Grade, and Risk Level."""
        if use_color:
            sep = click.style("  " + "─" * 50, fg="bright_black")
            click.echo(sep)
            click.echo(
                click.style("  Analysis Summary", fg="white", bold=True)
            )
            click.echo(sep)
            click.echo(
                "  " +
                click.style("score      ", fg="bright_black") +
                click.style(str(result.score), fg=self._score_color(result.score), bold=True) +
                click.style("/100", fg="bright_black")
            )
            click.echo(
                "  " +
                click.style("grade      ", fg="bright_black") +
                click.style(result.grade, fg=self._grade_color(result.grade), bold=True)
            )
            click.echo(
                "  " +
                click.style("risk       ", fg="bright_black") +
                click.style(
                    result.risk_level.value.upper(),
                    fg=self._risk_color(result.risk_level.value),
                    bold=True,
                )
            )
            click.echo(sep)
            click.echo()
        else:
            sep = "  " + "─" * 50
            click.echo(sep)
            click.echo("  Analysis Summary")
            click.echo(sep)
            click.echo(f"  score      {result.score}/100")
            click.echo(f"  grade      {result.grade}")
            click.echo(f"  risk       {result.risk_level.value.upper()}")
            click.echo(sep)
            click.echo()

    # ── Issues list ───────────────────────────────────────────────────────────

    def _display_issues(self, issues: list[Issue], use_color: bool) -> None:
        """Display issues ordered from highest to lowest severity."""
        sorted_issues = sorted(
            issues,
            key=lambda issue: self.SEVERITY_ORDER.index(issue.severity.value),
        )

        if not sorted_issues:
            if use_color:
                click.echo(
                    "  " +
                    click.style("✔ ", fg="green", bold=True) +
                    click.style("No issues found.", fg="green")
                )
            else:
                click.echo("  No issues found.")
            return

        issue_count = len(sorted_issues)
        if use_color:
            click.echo(
                "  " +
                click.style("Issues Found  ", fg="bright_black") +
                click.style(str(issue_count), fg="white", bold=True)
            )
        else:
            click.echo(f"  Issues Found  {issue_count}")
        click.echo()

        for i, issue in enumerate(sorted_issues, 1):
            self._display_issue(issue, i, use_color)

    def _display_issue(self, issue: Issue, index: int, use_color: bool) -> None:
        """Display a single issue with appropriate formatting."""
        severity_value = issue.severity.value

        if use_color:
            color = self.SEVERITY_COLORS.get(severity_value, "white")
            icon  = self.SEVERITY_ICONS.get(severity_value, "·")

            # Header line: index + severity badge + title
            click.echo(
                "  " +
                click.style(f"{index}. ", fg="bright_black") +
                click.style(f"{icon} {severity_value.upper()}", fg=color, bold=True) +
                click.style("  " + issue.title, fg="white")
            )
            # Check name
            click.echo(
                click.style(f"     check   {issue.check}", fg="bright_black")
            )
            # Description
            if issue.description:
                click.echo(
                    "     " + click.style(issue.description, fg="bright_black")
                )
            # Recommendation — cyan to match banner accent
            if issue.recommendation:
                click.echo(
                    "     " +
                    click.style("→ ", fg="cyan", bold=True) +
                    click.style(issue.recommendation, fg="cyan")
                )
            # CWE / OWASP tags
            tags: list[str] = []
            if issue.cwe:
                tags.append(click.style(f"CWE:{issue.cwe}", fg="bright_black"))
            if issue.owasp:
                tags.append(click.style(f"OWASP:{issue.owasp}", fg="bright_black"))
            if tags:
                click.echo("     " + "  ".join(tags))
        else:
            severity_prefix = f"[{severity_value.upper()}]"
            click.echo(f"  {index}. {severity_prefix} {issue.title}")
            click.echo(f"     check   {issue.check}")
            if issue.description:
                click.echo(f"     {issue.description}")
            if issue.recommendation:
                click.echo(f"     -> {issue.recommendation}")
            if issue.cwe:
                click.echo(f"     CWE:{issue.cwe}")
            if issue.owasp:
                click.echo(f"     OWASP:{issue.owasp}")

        click.echo()

    # ── Inline spinner (legacy — prefer ProgressIndicator context manager) ────

    def start_progress(self, message: str = "Analyzing") -> None:
        """Start the progress spinner indicator.

        Args:
            message: The message to display alongside the spinner.
        """
        self._spinner_active = True
        self._spinner_thread = threading.Thread(
            target=self._run_spinner, args=(message,), daemon=True
        )
        self._spinner_thread.start()

    def stop_progress(self) -> None:
        """Stop the progress spinner indicator."""
        self._spinner_active = False
        if self._spinner_thread is not None:
            self._spinner_thread.join(timeout=2.0)
            self._spinner_thread = None
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()

    def _run_spinner(self, message: str) -> None:
        """Run the spinner animation in a background thread."""
        spinner = cycle(self.SPINNER_FRAMES)
        while self._spinner_active:
            frame = next(spinner)
            sys.stderr.write(
                f"\r  {click.style(frame, fg='cyan')} "
                f"{click.style(message, fg='bright_black')}..."
            )
            sys.stderr.flush()
            time.sleep(0.1)

    # ── Color helpers ─────────────────────────────────────────────────────────

    def _score_color(self, score: int) -> str:
        if score >= 90:
            return "green"
        elif score >= 70:
            return "yellow"
        elif score >= 50:
            return "bright_red"
        return "red"

    def _grade_color(self, grade: str) -> str:
        return {
            "A": "green",
            "B": "cyan",
            "C": "yellow",
            "D": "bright_red",
            "F": "red",
        }.get(grade, "white")

    def _risk_color(self, risk_level: str) -> str:
        return {
            "critical": "red",
            "high":     "bright_red",
            "medium":   "yellow",
            "low":      "blue",
        }.get(risk_level, "white")
