# Development

## Prerequisites

- [uv](https://docs.astral.sh/uv/) - Python version management, dependency locking, and task runner
- Python 3.11+

Install uv if you don't have it:

```bash
pip install uv
# or on macOS/Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

---

## Setup

```bash
git clone <repo-url> pyqualify
cd pyqualify

# Install all dependencies including dev extras
uv sync --extra dev
```

uv automatically creates a `.venv` and uses the pinned Python version from `uv.lock`. No manual `python -m venv` needed.

---

## Running the Tool

```bash
# Interactive mode
uv run pyqualify

# Direct commands
uv run pyqualify web https://example.com
uv run pyqualify code ./src
uv run pyqualify api https://api.example.com

# With output options
uv run pyqualify web https://example.com --pdf
uv run pyqualify web https://example.com --json

# Tool filtering
uv run pyqualify web https://example.com --only security-headers,seo
uv run pyqualify code ./src --disable test-gaps

# List available tools
uv run pyqualify tools
uv run pyqualify tools code

# First-time setup
uv run pyqualify setup
```

---

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage report
uv run pytest --cov=pyqualify --cov-report=html

# Run a specific test file
uv run pytest tests/test_scoring_engine.py

# Run a specific test class or function
uv run pytest tests/test_ai_engine.py::TestParseResponse
uv run pytest tests/test_ai_engine.py::TestParseResponse::test_parses_valid_response

# Run tests matching a keyword
uv run pytest -k "scoring"

# Verbose output
uv run pytest -v

# Stop on first failure
uv run pytest -x
```

> **Note:** `tests/test_config_editor.py` requires `curses`, which is not available on Windows. Skip it with `--ignore=tests/test_config_editor.py` if needed.

---

## Project Structure

```
pyqualify/
    pyproject.toml        project metadata, dependencies, tool config
    uv.lock               pinned dependency versions
    pyqualify/            source package
    tests/                test suite (mirrors pyqualify/ structure)
    docs/                 documentation
```

See [architecture.md](architecture.md) for a full breakdown of the source layout.

---

## Adding Dependencies

```bash
# Runtime dependency
uv add httpx

# Dev-only dependency
uv add --dev pytest-mock

# Optional dependency (e.g. Anthropic SDK)
uv add anthropic
```

After adding, `uv.lock` is updated automatically. Commit both `pyproject.toml` and `uv.lock`.

---

## Code Style

The project uses standard Python conventions:

- **Type hints** on all public functions and methods
- **Docstrings** on all public classes and methods (Google style)
- **Dataclasses** for all data models - no mutable class attributes
- **Protocols** for all component interfaces - no abstract base classes
- **`from __future__ import annotations`** in files that need forward references

No linter or formatter is enforced by CI currently. Recommended: `ruff` for linting, `black` for formatting.

```bash
uv add --dev ruff black
uv run ruff check pyqualify/
uv run black pyqualify/ tests/
```

---

## Writing Tests

Tests live in `tests/` and mirror the source structure - one test file per source module.

```
pyqualify/ai/engine.py          ->  tests/test_ai_engine.py
pyqualify/scoring/engine.py     ->  tests/test_scoring_engine.py
```

### Fixtures

Common fixtures are defined at the top of each test file. No shared `conftest.py` currently - add one if fixtures need to be shared across multiple test files.

### Async Tests

The project uses `pytest-asyncio` with `asyncio_mode = "auto"` (set in `pyproject.toml`). Async test methods work without any decorator:

```python
async def test_process_findings(self, engine: AIEngine) -> None:
    result = await engine.process_findings(findings, context)
    assert len(result) == 2
```

### Mocking the AI Engine

Use `unittest.mock.AsyncMock` to mock `_call_llm` and avoid real API calls:

```python
from unittest.mock import AsyncMock, patch

async def test_successful_processing(self, engine: AIEngine) -> None:
    with patch.object(engine, "_call_llm", new_callable=AsyncMock) as mock:
        mock.return_value = {"issues": [...]}
        result = await engine.process_findings(findings, context)
    assert len(result) == 2
```

### Mocking ConfigManager

Patch `CONFIG_DIR` and `CONFIG_FILE` to avoid touching the real `~/.pyqualify/` directory:

```python
from unittest.mock import patch

def test_something(self, tmp_path):
    config_dir = tmp_path / ".pyqualify"
    config_file = config_dir / "config.toml"
    with patch.object(ConfigManager, "CONFIG_DIR", config_dir):
        with patch.object(ConfigManager, "CONFIG_FILE", config_file):
            manager = ConfigManager()
            # ...
```

---

## Adding a New Analyzer

1. Create `pyqualify/analyzers/my_analyzer.py` implementing `AnalyzerProtocol`:

```python
from pyqualify.ai.protocol import AIEngineProtocol
from pyqualify.logging.logger import PyqualifyLogger
from pyqualify.models import AnalysisConfig, AnalysisResult, RawFinding
from pyqualify.scoring.engine import ScoringEngine
from pyqualify.tool_registry import ToolSelector

class MyAnalyzer:
    def __init__(self, ai_engine: AIEngineProtocol, logger: PyqualifyLogger) -> None:
        self._ai_engine = ai_engine
        self._logger = logger
        self._scoring = ScoringEngine()

    async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult:
        selector = ToolSelector.from_config(category="my-category", config=config)
        findings: list[RawFinding] = []

        if selector.is_enabled("my-tool"):
            findings += await self._run_my_tool(target)

        issues = await self._ai_engine.process_findings(findings, context)
        score = self._scoring.calculate_score(issues)
        # ... build and return AnalysisResult ...
```

2. Add the new category and its tools to `TOOL_REGISTRY` in `pyqualify/tool_registry.py`.

3. Add a prompt builder to `pyqualify/ai/prompts.py`.

4. Register the analyzer in `_build_container()` in `pyqualify/cli/main.py`.

5. Add a Click command in `pyqualify/cli/main.py`.

6. Add tests in `tests/test_my_analyzer.py`.

---

## Adding a New AI Provider

1. Add defaults to `_PROVIDER_DEFAULTS` in `pyqualify/ai/engine.py`:

```python
"myprovider": {
    "base_url": "https://api.myprovider.com/v1",
    "model": "my-model-name",
},
```

2. If the provider uses an OpenAI-compatible API, no further changes are needed - the existing `_call_openai_compat()` path handles it. Note that `response_format: json_object` is only sent to `openai` and `google`; if your provider doesn't support it, add it to the exclusion list in `_call_openai_compat()`.

3. If it uses a custom API, add a `_call_myprovider()` method and route to it in `_call_llm()`.

4. Add the provider to the setup wizard catalogue `_PROVIDERS` in `pyqualify/cli/main.py`.

---

## Environment Variables

All `PYQUALIFY_`-prefixed environment variables are picked up automatically by `ConfigManager`. The prefix is stripped and the key lowercased:

```bash
export PYQUALIFY_API_KEY=sk-your-key
export PYQUALIFY_PROVIDER=openai
export PYQUALIFY_MODEL=gpt-4o
export PYQUALIFY_TIMEOUT=60
export PYQUALIFY_AI_TIMEOUT=120
export PYQUALIFY_MAX_RETRIES=5
export PYQUALIFY_RETRY_DELAY=1.0
export PYQUALIFY_LOG_LEVEL=DEBUG
export PYQUALIFY_LOG_FILE=/tmp/pyqualify.log
export PYQUALIFY_RATE_LIMIT_BURST=100
export PYQUALIFY_RATE_LIMIT_WINDOW=30
export PYQUALIFY_EXTRA_EXTENSIONS=.tpl,.tmpl
```

Copy `.env.example` to `.env` for local development.

---

## Building and Installing

```bash
# Build a wheel
uv build

# Install locally in editable mode (already done by uv sync)
uv pip install -e .

# Update the lock file after changing dependencies
uv lock
```

---

## Releasing

1. Bump `version` in `pyproject.toml`
2. Update `__version__` in `pyqualify/__init__.py`
3. Commit and tag: `git tag v0.2.0`
4. Build: `uv build`
5. Publish: `uv publish` (requires PyPI credentials)
