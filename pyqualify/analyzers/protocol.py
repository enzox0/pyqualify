"""Protocol definition for analysis engines."""

from typing import Protocol

from pyqualify.models import AnalysisConfig, AnalysisResult


class AnalyzerProtocol(Protocol):
    """Interface for all analyzers.

    All analyzer implementations (Web, Code, API) must conform to this
    protocol, enabling dependency injection and independent testing.
    """

    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:
        """Run analysis on the given target and return structured results.

        Args:
            target: The analysis target (URL, file path, or API base URL).
            config: Configuration for the analysis run.

        Returns:
            A complete AnalysisResult with score, grade, risk level, and issues.
        """
        ...
