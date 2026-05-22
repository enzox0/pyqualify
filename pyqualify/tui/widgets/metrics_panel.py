"""MetricsPanel widget for the PyQualify TUI dashboard.

Displays the analysis score with a color-coded progress bar, letter grade,
risk level, and issue counts grouped by severity.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
"""

from __future__ import annotations

from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget

from pyqualify.models import AnalysisResult

# Score color thresholds (Req 3.1)
# green 90-100, yellow 70-89, orange 50-69, red 0-49
SCORE_COLORS: list[tuple[int, str]] = [
    (90, "green"),
    (70, "yellow"),
    (50, "#ff8800"),
    (0, "red"),
]

# Grade color mapping (Req 3.2)
# green for A, yellow for B and C, orange for D, red for F
GRADE_COLORS: dict[str, str] = {
    "A": "green",
    "B": "yellow",
    "C": "yellow",
    "D": "#ff8800",
    "F": "red",
    "-": "grey50",
}

# Risk level color mapping using severity colors (Req 3.3)
# red for critical, bright red for high, yellow for medium, blue for low
RISK_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "#ff5555",
    "medium": "yellow",
    "low": "blue",
    "-": "grey50",
}

# Severity colors for issue counts (Req 3.4)
SEVERITY_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "#ff5555",
    "medium": "yellow",
    "low": "blue",
    "info": "grey50",
}

# Default issue counts with all severities at 0 (Req 3.5)
DEFAULT_ISSUE_COUNTS: dict[str, int] = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
}


def _get_score_color(score: int) -> str:
    """Return the color for a given score value."""
    for threshold, color in SCORE_COLORS:
        if score >= threshold:
            return color
    return "red"


class MetricsPanel(Widget):
    """Displays score, grade, risk level, and issue counts.

    Renders a color-coded progress bar for the score, a letter grade
    with matching color threshold, the risk level with severity color
    mapping, and issue counts grouped by severity level.

    Default idle state shows score=0, grade="-", risk="-", counts=0.
    """

    DEFAULT_CSS = """
    MetricsPanel {
        height: 100%;
        width: 100%;
        padding: 1 1;
    }
    """

    BORDER_TITLE = "Metrics"

    # Reactive properties for live updates
    score: reactive[int] = reactive(0)
    grade: reactive[str] = reactive("-")
    risk_level: reactive[str] = reactive("-")
    issue_counts: reactive[dict[str, int]] = reactive(
        lambda: dict(DEFAULT_ISSUE_COUNTS)
    )

    def update_from_result(self, result: AnalysisResult) -> None:
        """Update all metrics from an AnalysisResult.

        Args:
            result: The completed analysis result containing score,
                    grade, risk_level, and issues.
        """
        self.score = result.score
        self.grade = result.grade
        self.risk_level = result.risk_level.value
        # Count issues by severity
        counts = dict(DEFAULT_ISSUE_COUNTS)
        for issue in result.issues:
            severity_key = issue.severity.value
            if severity_key in counts:
                counts[severity_key] += 1
        self.issue_counts = counts

    def render(self) -> Text:
        """Render the metrics panel content.

        The progress bar width adapts to the available widget width,
        ensuring proper reflow on terminal resize (Req 1.3).
        """
        text = Text()

        # Section: Score with progress bar
        text.append("SCORE", style="bold white")
        text.append("\n")
        score_color = _get_score_color(self.score)
        # Render score value
        text.append(f"  {self.score}", style=f"bold {score_color}")
        text.append("/100\n", style="grey50")
        # Render a text-based progress bar that adapts to available width
        # Use the widget's content width minus padding (2 chars indent)
        available_width = self.size.width - 4 if self.size.width > 6 else 20
        bar_width = min(max(available_width, 10), 40)
        filled = round(self.score / 100 * bar_width)
        empty = bar_width - filled
        text.append("  ")
        text.append("█" * filled, style=score_color)
        text.append("░" * empty, style="grey30")
        text.append("\n\n")

        # Section: Grade
        text.append("GRADE", style="bold white")
        text.append("\n")
        grade_color = GRADE_COLORS.get(self.grade, "grey50")
        text.append(f"  {self.grade}", style=f"bold {grade_color}")
        text.append("\n\n")

        # Section: Risk Level
        text.append("RISK", style="bold white")
        text.append("\n")
        risk_color = RISK_COLORS.get(self.risk_level, "grey50")
        risk_display = self.risk_level.upper() if self.risk_level != "-" else "-"
        text.append(f"  {risk_display}", style=f"bold {risk_color}")
        text.append("\n\n")

        # Section: Issue Counts by Severity
        text.append("ISSUES", style="bold white")
        text.append("\n")
        counts = self.issue_counts
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = counts.get(severity, 0)
            sev_color = SEVERITY_COLORS.get(severity, "white")
            label = severity.upper().ljust(9)
            text.append(f"  {label}", style=sev_color)
            text.append(f"{count}\n", style="white")

        return text

    def watch_score(self, value: int) -> None:
        """Trigger re-render when score changes."""
        self.refresh()

    def watch_grade(self, value: str) -> None:
        """Trigger re-render when grade changes."""
        self.refresh()

    def watch_risk_level(self, value: str) -> None:
        """Trigger re-render when risk level changes."""
        self.refresh()

    def watch_issue_counts(self, value: dict[str, int]) -> None:
        """Trigger re-render when issue counts change."""
        self.refresh()
