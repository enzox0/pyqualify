"""Protocol definition for report generation."""

from typing import Protocol

from pyqualify.models import AnalysisResult


class ReportGeneratorProtocol(Protocol):
    """Interface for report generation.

    Defines the contract for components that produce analysis output,
    whether for terminal display or file-based reports.
    """

    def generate_cli_output(self, result: AnalysisResult, use_color: bool = True) -> None:
        """Display results in the terminal with color coding.

        Args:
            result: The complete analysis result to display.
            use_color: Whether to use color-coded output. Falls back to
                plain text with severity prefixes when False.
        """
        ...

    def generate_html_report(self, result: AnalysisResult, output_path: str) -> None:
        """Generate a self-contained HTML dashboard report.

        Args:
            result: The complete analysis result to render.
            output_path: File path where the HTML report will be written.

        Raises:
            ReportError: If the output path is unwritable or generation fails.
        """
        ...
