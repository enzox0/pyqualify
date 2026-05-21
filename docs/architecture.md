# Architecture

PyQualify follows a layered pipeline architecture. Each analysis run flows through five distinct layers, with clean boundaries enforced by Python protocols.

```
CLI Layer
    |
    v
Analysis Engine (Web / Code / API)
    |
    v
AI Engine (OpenAI / Anthropic / Google / Groq)
    |
    v
Scoring Engine
    |
    v
Report Generator (CLI / PDF)        TUI Dashboard (Textual)
```

---

## Layers

### CLI Layer - `pyqualify/cli/`

Entry point for all user interaction. Built with [Click](https://click.palletsprojects.com/).

| File | Responsibility |
|------|---------------|
| `main.py` | Command group, subcommands (`web`, `code`, `api`, `dashboard`, `tools`, `config`), interactive menu, DI wiring |
| `progress.py` | Thread-based spinner shown during analysis |
| `validators.py` | URL, path, and filename validation for CLI arguments |

The CLI wires the dependency injection container on each invocation and delegates all work to the analysis layer. It never calls the AI engine or scoring engine directly.

### Analysis Engines - `pyqualify/analyzers/`

Three independent analyzers, each implementing `AnalyzerProtocol`:

```python
async def analyze(self, target: str, config: AnalysisConfig) -> AnalysisResult
```

| Analyzer | Target | Tools |
|----------|--------|-------|
| `WebAnalyzer` | URL | security-headers, forms, seo, accessibility, performance, links, captcha, smuggling-headers, case-sensitivity, json-hijacking, open-redirect, server-version-disclosure, dom-xss |
| `CodeAnalyzer` | File or directory | security, bug-risks, quality, test-gaps, dependencies, audit-log, case-sensitivity, known-vulnerabilities, password-policy |
| `APIAnalyzer` | Base URL | authentication, response-integrity, injection, rate-limiting, schema-conformance, audit-log-manipulation, captcha-bypass, http-request-smuggling, case-sensitivity, json-hijacking, open-redirect, server-version-disclosure, internal-ip-leakage, application-dos |

Each analyzer produces a list of `RawFinding` objects, passes them to the AI engine, then feeds the enriched `Issue` list to the scoring engine. Individual tools can be enabled or disabled per run via `AnalysisConfig.enabled_tools` / `disabled_tools`.

### Tool Registry - `pyqualify/tool_registry.py`

Central registry of all named tools per analyzer category. Used by the CLI `tools` command and by each analyzer to gate which checks run.

```python
from pyqualify.tool_registry import TOOL_REGISTRY, ToolSelector

# Check if a tool is enabled for this run
selector = ToolSelector.from_config(category="api", config=analysis_config)
if selector.is_enabled("injection"):
    findings += await self._test_injection(target)
```

`ToolSelector` supports three modes:
- **All enabled** (default) — no filtering specified
- **Whitelist** — `only` list provided; all other tools are skipped
- **Blacklist** — `exclude` list provided; listed tools are skipped

### AI Engine - `pyqualify/ai/`

Handles LLM communication with retry logic and multi-provider support.

```
AIEngine
  |-- _build_client()       - instantiates OpenAI / Anthropic / Google / Groq client
  |-- process_findings()    - orchestrates prompt -> LLM -> parse with retries
  |-- _call_openai_compat() - OpenAI and Google Gemini (OpenAI-compatible API)
  |-- _call_anthropic()     - Anthropic Messages API
  |-- _parse_response()     - validates and converts JSON -> Issue objects
  |-- _fallback_issues()    - returns INFO-severity issues when all retries fail
```

**Provider routing:**

| Provider | Client | Notes |
|----------|--------|-------|
| `openai` | `openai.AsyncOpenAI` | Default; uses `response_format: json_object` |
| `google` | `openai.AsyncOpenAI` | Gemini's OpenAI-compatible endpoint; uses `response_format: json_object` |
| `anthropic` | `anthropic.AsyncAnthropic` | Requires `uv add anthropic`; strips markdown fences from responses |
| `groq` | `openai.AsyncOpenAI` | Groq's OpenAI-compatible endpoint; does NOT use `response_format: json_object` |

**Retry behaviour:** up to `max_retries` attempts (default 3) with `retry_delay` seconds between each (default 2.0s). On total failure, `_fallback_issues()` returns one `INFO`-severity issue per raw finding so the pipeline always completes.

### Scoring Engine - `pyqualify/scoring/`

Pure function logic - no I/O, no external dependencies.

| Method | Logic |
|--------|-------|
| `calculate_score(issues)` | Start at 100, subtract per-severity penalties (CRITICAL -20, HIGH -10, MEDIUM -5, LOW -2, INFO 0), clamp to 0-100 |
| `derive_grade(score)` | A >=90, B >=80, C >=70, D >=60, F otherwise |
| `derive_risk_level(issues)` | Highest severity present: CRITICAL > HIGH > MEDIUM > LOW |

### Report Generators - `pyqualify/reporting/`

| Generator | Output | Protocol method |
|-----------|--------|----------------|
| `CLIFormatter` | Color-coded terminal output sorted by severity | `generate_cli_output()` |
| `PDFReportGenerator` | ReportLab-based PDF saved to `~/Documents/PyQualify/` | `generate_pdf_report()` |
| `HTMLDashboardGenerator` | Self-contained HTML file via Jinja2 template | `generate_html_report()` |

`CLIFormatter` and `PDFReportGenerator` are registered in the DI container and used by all CLI commands. `HTMLDashboardGenerator` is available in the package but not wired into the CLI by default.

### TUI Dashboard - `pyqualify/tui/`

A full-screen interactive dashboard built with [Textual](https://textual.textualize.io/). Launched via `pyqualify dashboard`.

```
DashboardApp (App)
  |-- DashboardScreen (Screen)
  |     |-- HeaderPanel        - tool name, version, status indicators
  |     |-- MetricsPanel       - live score, grade, risk level, issue counts
  |     |-- IssuesTable        - scrollable table of discovered issues
  |     |-- IssueDetailPanel   - full issue details (shown on Enter)
  |     |-- LogPanel           - real-time log feed
  |     `-- NavigationBar      - context-sensitive keyboard shortcut hints
  |
  `-- AnalysisRunner           - resolves analyzer, runs analysis, emits messages
```

**Message flow:**

| Message | Emitted by | Consumed by |
|---------|-----------|-------------|
| `ProgressUpdate` | `AnalysisRunner` | `DashboardApp` → `HeaderPanel` |
| `IssueDiscovered` | `AnalysisRunner` | `DashboardApp` → `IssuesTable`, `MetricsPanel` |
| `LogEmitted` | `AnalysisRunner` + `_LogPanelHandler` | `DashboardApp` → `LogPanel` |
| `AnalysisComplete` | `AnalysisRunner` | `DashboardApp` → `MetricsPanel`, `HeaderPanel` |
| `AnalysisError` | `AnalysisRunner` | `DashboardApp` → `HeaderPanel`, `LogPanel` |

**Key behaviours:**
- Requires a terminal of at least **80×24** characters; exits with code 1 if too small
- Auto-starts analysis when both `mode` and `target` are provided on launch
- Stall detection: emits a warning if no progress for 30 seconds
- Rendering error recovery: graceful shutdown after 3 consecutive render errors within 10 seconds
- `Ctrl+C` exits with code 130 (standard SIGINT convention)
- Python's `logging` module is bridged into the `LogPanel` via `_LogPanelHandler`

See [TUI Dashboard](tui-dashboard.md) for usage details.

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

The container is wired fresh on each CLI invocation inside `_build_container()` in `cli/main.py`.

**Singletons per run:** `ConfigManager`, `PyqualifyLogger`, `AIEngine`, `CLIFormatter`, `PDFReportGenerator`

**Transients (fresh instance per resolve):** `WebAnalyzer`, `CodeAnalyzer`, `APIAnalyzer` — each gets a fresh `httpx.AsyncClient` so connection state doesn't leak between runs.

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
| `AnalysisConfig` | timeout, max_links, rate_limit settings, pdf_output, json_output, enabled_tools, disabled_tools, extra_extensions |
| `AIConfig` | api_key, provider, base_url, model, timeout, max_retries, retry_delay |
| `LogConfig` | level, log_file |
| `AnalysisContext` | mode, target, additional_context dict |

TUI-specific models live in `pyqualify/tui/models.py`:

| Type | Purpose |
|------|---------|
| `StatusState` | Component identifier, state, and label for HeaderPanel status indicators |
| `LogEntry` | Timestamp, level, and message for a single LogPanel entry |
| `ProgressState` | Phase name, percent, and stall flag for progress tracking |

---

## Utilities - `pyqualify/utils.py`

Two shared helper functions used across analyzers and the AI engine:

| Function | Purpose |
|----------|---------|
| `truncate_evidence(evidence, max_length=500)` | Truncates long evidence strings with a `"... [truncated]"` indicator |
| `resolve_location(location, fallback="unknown")` | Returns `fallback` if `location` is `None` or empty |

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

`ConfigEditor` provides a curses-based interactive editor (nano-style keybindings). On Windows, curses is unavailable — use `pyqualify config set` instead.

---

## Logging - `pyqualify/logging/`

`PyqualifyLogger` wraps Python's standard `logging` module. All log output goes to stderr. An optional file handler is added when `log_file` is configured.

Log format: `YYYY-MM-DD HH:MM:SS [LEVEL] [pyqualify.module] message`

Child loggers are created per module name (e.g. `pyqualify.web_analyzer`, `pyqualify.ai_engine`) so log output is filterable by component.

When the TUI dashboard is active, a `_LogPanelHandler` is attached to the root `pyqualify` logger and routes all log records into the `LogPanel` widget in real time.

---

## Async I/O

All network operations use `httpx.AsyncClient`. The CLI runs the async analysis coroutine with `asyncio.run()`. Analyzers use `asyncio.wait_for()` with per-operation timeouts to prevent hangs on slow targets.

The TUI dashboard runs the analysis coroutine as an `asyncio.Task` managed by Textual's event loop, allowing the UI to remain responsive during analysis.

---

## Protocol Interfaces

All major component boundaries are defined as Python `Protocol` classes:

| Protocol | Implemented by |
|----------|---------------|
| `AnalyzerProtocol` | `WebAnalyzer`, `CodeAnalyzer`, `APIAnalyzer` |
| `AIEngineProtocol` | `AIEngine` |
| `ReportGeneratorProtocol` | `CLIFormatter`, `PDFReportGenerator`, `HTMLDashboardGenerator` |

This allows any component to be swapped or mocked in tests without modifying calling code.

---

## Directory Structure

```
pyqualify/
    pyproject.toml
    uv.lock
    README.md
    docs/
        index.md
        architecture.md
        configuration.md
        development.md
        tui-dashboard.md
        web-analysis.md
        code-analysis.md
        api-analysis.md
        scoring.md
        pdf-reports.md
    pyqualify/
        __init__.py           version
        __main__.py           python -m pyqualify entry point
        models.py             all dataclasses and enums
        container.py          DI container
        utils.py              truncate_evidence, resolve_location
        tool_registry.py      TOOL_REGISTRY, ToolSelector
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
            pdf_generator.py
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
        tui/
            app.py            DashboardApp (Textual App)
            screens.py        DashboardScreen layout
            runner.py         AnalysisRunner (progress events)
            messages.py       Textual Message subclasses
            models.py         TUI-specific dataclasses
            dashboard.tcss    Textual CSS stylesheet
            widgets/
                header_panel.py
                metrics_panel.py
                issues_table.py
                issue_detail_panel.py
                log_panel.py
                navigation_bar.py
                help_modal.py
    tests/
        test_*.py             one file per module
```
