# Architecture

PyQualify follows a layered pipeline architecture. Each analysis run flows through five distinct layers, with clean boundaries enforced by Python protocols.

```
CLI Layer
    |
    v
Analysis Engine (Web / Code / API)
    |
    v
AI Engine (OpenAI / Anthropic / Google)
    |
    v
Scoring Engine
    |
    v
Report Generator (CLI / HTML)
```

---

## Layers

### CLI Layer - `pyqualify/cli/`

Entry point for all user interaction. Built with [Click](https://click.palletsprojects.com/).

| File | Responsibility |
|------|---------------|
| `main.py` | Command group, subcommands (`web`, `code`, `api`, `config`), interactive menu, DI wiring |
| `progress.py` | Thread-based spinner shown during analysis |
| `validators.py` | URL, path, and filename validation for CLI arguments |

The CLI wires the dependency injection container on each invocation and delegates all work to the analysis layer. It never calls the AI engine or scoring engine directly.

### Analysis Engines - `pyqualify/analyzers/`

Three independent analyzers, each implementing `AnalyzerProtocol`:

```python
async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult
```

| Analyzer | Target | Checks |
|----------|--------|--------|
| `WebAnalyzer` | URL | Security headers, CSRF, SEO, accessibility, performance, broken/suspicious links |
| `CodeAnalyzer` | File or directory | Injection, hardcoded secrets, deserialization, path traversal, bug risks, quality, test gaps, dependencies |
| `APIAnalyzer` | Base URL | Authentication enforcement, response integrity, schema conformance, injection, rate limiting |

Each analyzer produces a list of `RawFinding` objects, passes them to the AI engine, then feeds the enriched `Issue` list to the scoring engine.

### AI Engine - `pyqualify/ai/`

Handles LLM communication with retry logic and multi-provider support.

```
AIEngine
  |-- _build_client()       - instantiates OpenAI / Anthropic / Google client
  |-- process_findings()    - orchestrates prompt -> LLM -> parse with retries
  |-- _call_openai_compat() - OpenAI and Google Gemini (OpenAI-compatible API)
  |-- _call_anthropic()     - Anthropic Messages API
  |-- _parse_response()     - validates and converts JSON -> Issue objects
  |-- _fallback_issues()    - returns INFO-severity issues when all retries fail
```

**Provider routing:**

| Provider | Client | Notes |
|----------|--------|-------|
| `openai` | `openai.AsyncOpenAI` | Default |
| `google` | `openai.AsyncOpenAI` | Uses Gemini's OpenAI-compatible endpoint |
| `anthropic` | `anthropic.AsyncAnthropic` | Requires `uv add anthropic` |

**Retry behaviour:** up to `max_retries` attempts (default 3) with `retry_delay` seconds between each (default 2.0s). On total failure, `_fallback_issues()` returns one `INFO`-severity issue per raw finding so the pipeline always completes.

### Scoring Engine - `pyqualify/scoring/`

Pure function logic - no I/O, no external dependencies.

| Method | Logic |
|--------|-------|
| `calculate_score(issues)` | Start at 100, subtract per-severity penalties (CRITICAL -20, HIGH -10, MEDIUM -5, LOW -2, INFO 0), clamp to 0-100 |
| `derive_grade(score)` | A >=90, B >=80, C >=70, D >=60, F otherwise |
| `derive_risk_level(issues)` | Highest severity present: CRITICAL > HIGH > MEDIUM > LOW |

### Report Generators - `pyqualify/reporting/`

Both implement `ReportGeneratorProtocol`:

```python
def generate_cli_output(self, result: AnalysisResult, use_color: bool = True) -> None
def generate_html_report(self, result: AnalysisResult, output_path: str) -> None
```

| Generator | Output |
|-----------|--------|
| `CLIFormatter` | Color-coded terminal output sorted by severity |
| `HTMLDashboardGenerator` | Self-contained HTML file via Jinja2 template (`templates/dashboard.html`) |

---

## Dependency Injection - `pyqualify/container.py`

A lightweight custom DI container. No third-party framework.

```python
container = Container()

# Transient - new instance on every resolve()
container.register(WebAnalyzer, lambda: WebAnalyzer(...))

# Singleton - created once, cached for all subsequent resolve() calls
container.register_singleton(PyqualifyLogger, lambda: PyqualifyLogger(...))

analyzer = container.resolve(WebAnalyzer)
```

The container is wired fresh on each CLI invocation inside `_build_container()` in `cli/main.py`. Singletons within a run (logger, AI engine, config manager) are shared; analyzers are transient so each run gets a fresh HTTP client.

---

## Data Models - `pyqualify/models.py`

All models are plain Python dataclasses. No ORM, no serialization framework.

```
RawFinding          - produced by analyzers before AI enrichment
    |
    v (AIEngine.process_findings)
Issue               - enriched with severity, CWE, OWASP, recommendation
    |
    v (ScoringEngine)
AnalysisResult      - score, grade, risk_level, issues[], summary, metadata
```

Key types:

| Type | Purpose |
|------|---------|
| `RawFinding` | check, category, location, evidence, context dict |
| `Issue` | check, severity, title, description, evidence, recommendation, cwe, owasp |
| `AnalysisResult` | score (0-100), grade (A-F), risk_level, issues, summary, metadata |
| `AnalysisConfig` | timeout, max_links, rate_limit settings, html_output, json_output |
| `AIConfig` | api_key, provider, base_url, model, timeout, max_retries, retry_delay |
| `LogConfig` | level, log_file |

---

## Configuration - `pyqualify/config/`

Three-layer precedence (lowest to highest):

```
Config file  (~/.pyqualify/config.toml)
    |
    v
Environment variables  (PYQUALIFY_* prefix)
    |
    v
CLI arguments  (passed at runtime)
```

`ConfigManager` merges all three sources on every `get()` call. The config file is TOML, written manually (Python's `tomllib` is read-only). Sensitive keys (`api_key`, `token`, `secret`, `password`) are masked in `list_all()` output.

`ConfigEditor` provides a curses-based interactive editor (nano-style keybindings). On Windows, curses is unavailable - use `pyqualify config set` instead.

---

## Logging - `pyqualify/logging/`

`PyqualifyLogger` wraps Python's standard `logging` module. All log output goes to stderr. An optional file handler is added when `log_file` is configured.

Log format: `YYYY-MM-DD HH:MM:SS [LEVEL] [pyqualify.module] message`

Child loggers are created per module name (e.g. `pyqualify.web_analyzer`, `pyqualify.ai_engine`) so log output is filterable by component.

---

## Async I/O

All network operations use `httpx.AsyncClient`. The CLI runs the async analysis coroutine with `asyncio.run()`. Analyzers use `asyncio.wait_for()` with per-operation timeouts to prevent hangs on slow targets.

---

## Protocol Interfaces

All major component boundaries are defined as Python `Protocol` classes:

| Protocol | Implemented by |
|----------|---------------|
| `AnalyzerProtocol` | `WebAnalyzer`, `CodeAnalyzer`, `APIAnalyzer` |
| `AIEngineProtocol` | `AIEngine` |
| `ReportGeneratorProtocol` | `CLIFormatter`, `HTMLDashboardGenerator` |

This allows any component to be swapped or mocked in tests without modifying calling code.

---

## Directory Structure

```
pyqualify-tool/
    pyproject.toml
    uv.lock
    README.md
    docs/
        index.md
        architecture.md
        configuration.md
        development.md
    pyqualify/
        __init__.py           version
        __main__.py           python -m pyqualify entry point
        models.py             all dataclasses and enums
        container.py          DI container
        utils.py              truncate_evidence, resolve_location
        cli/
            main.py           Click commands + DI wiring
            progress.py       spinner
            validators.py     input validation
        analyzers/
            web_analyzer.py
            code_analyzer.py
            api_analyzer.py
            protocol.py
        ai/
            engine.py         LLM client + retry logic
            prompts.py        prompt construction
            protocol.py
        reporting/
            cli_formatter.py
            html_generator.py
            protocol.py
            templates/
                dashboard.html
        scoring/
            engine.py
        config/
            manager.py
            editor.py
        logging/
            logger.py
    tests/
        test_*.py             one file per module
```
