"""AI engine implementation supporting OpenAI, Anthropic, and Google providers."""

import asyncio
import json
from typing import Any

from pyqualify.ai.prompts import PromptManager
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import AIConfig, AnalysisContext, AnalysisMode, Issue, RawFinding, Severity
from pyqualify.utils import resolve_location

# ── Provider defaults ─────────────────────────────────────────────────────────

_PROVIDER_DEFAULTS: dict[str, dict[str, str]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com",
        "model": "claude-3-5-sonnet-20241022",
    },
    "google": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.0-flash",
    },
}

_SYSTEM_PROMPT = (
    "You are a security and quality analysis assistant. "
    "Respond only with valid JSON."
)


class AIEngine:
    """LLM-based analysis engine with multi-provider support and retry logic.

    Supports OpenAI (GPT), Anthropic (Claude), and Google (Gemini) via their
    respective APIs. Anthropic and Google are accessed through an
    OpenAI-compatible shim so a single client interface is used throughout.
    """

    def __init__(self, config: AIConfig, logger: PyqualifyLogger) -> None:
        self._config = config
        self._logger = logger
        self._prompt_manager = PromptManager()
        self._provider = config.provider.lower().strip()

        # Resolve defaults for model and base_url
        defaults = _PROVIDER_DEFAULTS.get(self._provider, _PROVIDER_DEFAULTS["openai"])
        self._model = config.model or defaults["model"]
        self._base_url = config.base_url or defaults["base_url"]

        self._client = self._build_client()

    def _build_client(self) -> Any:
        """Instantiate the appropriate async client for the configured provider."""
        if self._provider == "anthropic":
            try:
                import anthropic  # type: ignore[import]
                return anthropic.AsyncAnthropic(api_key=self._config.api_key)
            except ImportError:
                raise RuntimeError(
                    "The 'anthropic' package is required for Claude models. "
                    "Install it with: uv add anthropic"
                )
        elif self._provider == "google":
            try:
                # Google Gemini exposes an OpenAI-compatible endpoint
                import openai
                return openai.AsyncOpenAI(
                    api_key=self._config.api_key,
                    base_url=self._base_url,
                )
            except ImportError:
                raise RuntimeError(
                    "The 'openai' package is required. Install it with: uv add openai"
                )
        else:
            # Default: OpenAI (also handles any custom OpenAI-compatible endpoint)
            import openai
            return openai.AsyncOpenAI(
                api_key=self._config.api_key,
                base_url=self._base_url,
            )

    # ── Public interface ──────────────────────────────────────────────────────

    async def process_findings(
        self, findings: list[RawFinding], context: AnalysisContext
    ) -> list[Issue]:
        """Process raw findings through the LLM with retry logic.

        Args:
            findings: Raw findings from an analyzer.
            context: Analysis context for prompt construction.

        Returns:
            Enriched Issue objects, or fallback INFO issues on total failure.
        """
        if not findings:
            return []

        prompt = self._build_prompt(findings, context)
        last_error: Exception | None = None

        for attempt in range(1, self._config.max_retries + 1):
            try:
                self._logger.debug(
                    "ai_engine",
                    f"[{self._provider}/{self._model}] attempt {attempt}/{self._config.max_retries}",
                )
                response = await self._call_llm(prompt)
                issues = self._parse_response(response)
                self._logger.info(
                    "ai_engine",
                    f"Processed {len(findings)} findings → {len(issues)} issues",
                )
                return issues
            except Exception as e:
                last_error = e
                self._logger.warning(
                    "ai_engine",
                    f"Attempt {attempt}/{self._config.max_retries} failed: {e}",
                )
                if attempt < self._config.max_retries:
                    await asyncio.sleep(self._config.retry_delay)

        self._logger.error(
            "ai_engine",
            f"All {self._config.max_retries} retries exhausted. Returning fallback issues.",
            exc=last_error,
        )
        return self._fallback_issues(findings)

    # ── Provider-specific LLM calls ───────────────────────────────────────────

    async def _call_llm(self, prompt: str) -> dict:
        """Dispatch to the correct provider call and return a parsed JSON dict."""
        if self._provider == "anthropic":
            return await self._call_anthropic(prompt)
        else:
            return await self._call_openai_compat(prompt)

    async def _call_openai_compat(self, prompt: str) -> dict:
        """Call an OpenAI-compatible endpoint (OpenAI or Google Gemini)."""
        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        # json_object mode is supported by OpenAI and Gemini but not all models
        if self._provider in ("openai", "google"):
            kwargs["response_format"] = {"type": "json_object"}

        response = await asyncio.wait_for(
            self._client.chat.completions.create(**kwargs),
            timeout=self._config.timeout,
        )
        content = response.choices[0].message.content or ""
        return json.loads(content)

    async def _call_anthropic(self, prompt: str) -> dict:
        """Call the Anthropic Messages API (Claude)."""
        response = await asyncio.wait_for(
            self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            ),
            timeout=self._config.timeout,
        )
        # Extract text from the first content block
        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content = block.text
                break

        # Claude may wrap JSON in markdown fences — strip them
        content = content.strip()
        if content.startswith("```"):
            lines = content.splitlines()
            content = "\n".join(
                line for line in lines
                if not line.startswith("```")
            ).strip()

        return json.loads(content)

    # ── Response parsing ──────────────────────────────────────────────────────

    def _parse_response(self, response: dict) -> list[Issue]:
        """Validate and convert the LLM JSON response into Issue objects."""
        if not isinstance(response, dict):
            raise ValueError("Response must be a JSON object")

        issues_data = response.get("issues")
        if not isinstance(issues_data, list):
            raise ValueError("Response must contain an 'issues' array")

        valid_severities = {s.value for s in Severity}
        issues: list[Issue] = []

        for item in issues_data:
            if not isinstance(item, dict):
                raise ValueError("Each issue must be a JSON object")

            required_fields = [
                "check", "severity", "title", "description",
                "evidence", "recommendation",
            ]
            for field_name in required_fields:
                if field_name not in item:
                    raise ValueError(f"Issue missing required field: {field_name}")

            severity_str = item["severity"]
            if severity_str not in valid_severities:
                raise ValueError(
                    f"Invalid severity '{severity_str}'. "
                    f"Must be one of: {', '.join(valid_severities)}"
                )

            issues.append(Issue(
                check=str(item["check"]),
                severity=Severity(severity_str),
                title=str(item["title"])[:200],
                description=str(item["description"])[:2000],
                evidence=str(item["evidence"])[:2000],
                recommendation=str(item["recommendation"])[:2000],
                cwe=item.get("cwe") if item.get("cwe") else None,
                owasp=item.get("owasp") if item.get("owasp") else None,
            ))

        return issues

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_prompt(self, findings: list[RawFinding], context: AnalysisContext) -> str:
        if context.mode == AnalysisMode.WEB:
            return self._prompt_manager.build_web_prompt(findings, context.target)
        elif context.mode == AnalysisMode.CODE:
            return self._prompt_manager.build_code_prompt(findings, context.target)
        elif context.mode == AnalysisMode.API:
            return self._prompt_manager.build_api_prompt(findings, context.target)
        return self._prompt_manager.build_web_prompt(findings, context.target)

    def _fallback_issues(self, findings: list[RawFinding]) -> list[Issue]:
        issues: list[Issue] = []
        for finding in findings:
            location = resolve_location(finding.location, fallback="unknown")
            issues.append(Issue(
                check=finding.check,
                severity=Severity.INFO,
                title=f"Unprocessed finding: {finding.check}"[:200],
                description=(
                    f"AI processing failed. Original finding from category "
                    f"'{finding.category}' at location '{location}'."
                )[:2000],
                evidence=finding.evidence[:2000],
                recommendation="Manual review recommended. AI enrichment was unavailable."[:2000],
                cwe=None,
                owasp=None,
            ))
        return issues
