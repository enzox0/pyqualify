"""Protocol definition for the AI engine interface."""

from typing import Protocol

from pyqualify.models import AnalysisContext, Issue, RawFinding


class AIEngineProtocol(Protocol):
    """Interface for AI-powered analysis.

    Defines the contract that any AI engine implementation must satisfy,
    enabling substitution of implementations without modifying calling code.
    """

    async def process_findings(
        self, findings: list[RawFinding], context: AnalysisContext
    ) -> list[Issue]:
        """Process raw findings through LLM and return enriched issues.

        Args:
            findings: Raw findings produced by an analyzer before AI enrichment.
            context: Analysis context for prompt construction (mode, target, etc.).

        Returns:
            A list of fully enriched Issue objects with severity, title,
            description, evidence, recommendation, and optional CWE/OWASP refs.
        """
        ...
