"""Tests for qaai.ai.protocol module."""

import asyncio

from pyqualify.ai.protocol import AIEngineProtocol
from pyqualify.models import AnalysisContext, AnalysisMode, Issue, RawFinding, Severity


class MockAIEngine:
    """A mock implementation that satisfies AIEngineProtocol."""

    async def process_findings(
        self, findings: list[RawFinding], context: AnalysisContext
    ) -> list[Issue]:
        """Return a mock issue for each finding."""
        return [
            Issue(
                check=f.check,
                severity=Severity.MEDIUM,
                title=f"Issue from {f.check}",
                description=f"Description for {f.check}",
                evidence=f.evidence,
                recommendation="Fix it.",
            )
            for f in findings
        ]


class TestAIEngineProtocol:
    """Tests for AIEngineProtocol interface."""

    def test_mock_satisfies_protocol(self):
        """A class implementing the required method satisfies the protocol."""
        engine: AIEngineProtocol = MockAIEngine()
        assert isinstance(engine, AIEngineProtocol)

    def test_process_findings_returns_issues(self):
        """process_findings returns a list of Issue objects."""
        engine: AIEngineProtocol = MockAIEngine()
        findings = [
            RawFinding(
                check="missing-csp",
                category="security",
                location="https://example.com",
                evidence="No CSP header",
            )
        ]
        context = AnalysisContext(
            mode=AnalysisMode.WEB,
            target="https://example.com",
        )
        result = asyncio.run(engine.process_findings(findings, context))
        assert len(result) == 1
        assert isinstance(result[0], Issue)
        assert result[0].check == "missing-csp"
        assert result[0].severity == Severity.MEDIUM

    def test_process_findings_empty_list(self):
        """process_findings handles empty findings list."""
        engine: AIEngineProtocol = MockAIEngine()
        context = AnalysisContext(
            mode=AnalysisMode.CODE,
            target="/src/main.py",
        )
        result = asyncio.run(engine.process_findings([], context))
        assert result == []

    def test_process_findings_multiple_findings(self):
        """process_findings processes multiple findings."""
        engine: AIEngineProtocol = MockAIEngine()
        findings = [
            RawFinding(
                check="check-1",
                category="security",
                location="loc1",
                evidence="ev1",
            ),
            RawFinding(
                check="check-2",
                category="quality",
                location="loc2",
                evidence="ev2",
            ),
        ]
        context = AnalysisContext(
            mode=AnalysisMode.API,
            target="https://api.example.com",
        )
        result = asyncio.run(engine.process_findings(findings, context))
        assert len(result) == 2
        assert result[0].check == "check-1"
        assert result[1].check == "check-2"

    def test_protocol_import_from_package(self):
        """AIEngineProtocol is importable from the ai package."""
        from pyqualify.ai import AIEngineProtocol as ImportedProtocol

        assert ImportedProtocol is AIEngineProtocol

