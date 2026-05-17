"""Report generation for CLI and HTML output."""

from pyqualify.reporting.cli_formatter import CLIFormatter
from pyqualify.reporting.protocol import ReportGeneratorProtocol

__all__ = ["CLIFormatter", "ReportGeneratorProtocol"]
