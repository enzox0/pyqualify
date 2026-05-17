# PyQualify - AI-Powered QA & Security Analysis Tool

PyQualify is a command-line tool that performs automated quality assurance and security analysis across three modes: **Web**, **Code**, and **API**. It leverages LLM-based intelligence to classify findings, produce severity ratings, and generate actionable recommendations.

## Features

- **Web Analysis** - Security headers, form CSRF detection, SEO completeness, accessibility compliance, performance signals, broken link detection
- **Code Analysis** - Security vulnerabilities, bug risk detection, code quality metrics, test gap identification, dependency risk assessment
- **API Analysis** - Authentication enforcement, response integrity, schema conformance, injection vector testing, rate limiting verification
- **AI-Powered Classification** - Findings are processed through an LLM for intelligent severity assignment, CWE/OWASP mapping, and contextual recommendations
- **Scoring & Grading** - Numeric score (0-100), letter grade (A-F), and risk level for every analysis run
- **HTML Dashboard Reports** - Self-contained HTML reports with charts, filterable issue tables, and executive summaries
- **Color-Coded CLI Output** - Severity-based coloring with graceful fallback for terminals without color support
- **Hierarchical Configuration** - TOML config file, environment variables, and CLI arguments with clear precedence
- **Interactive Config Editor** - Nano-like terminal editor for managing configuration

## Requirements

- [uv](https://docs.astral.sh/uv/) - used for Python version management, dependency locking, and running the project
- An API key for one of the supported AI providers:
  - **OpenAI** - GPT-4o, GPT-4-turbo, GPT-3.5-turbo, ...
  - **Anthropic** - Claude 3.5 Sonnet, Claude 3 Opus, ... (`uv add anthropic` required)
  - **Google** - Gemini 2.0 Flash, Gemini 1.5 Pro, ...

## Installation

```bash
git clone <repo-url> PyQualify-tool
cd PyQualify-tool

# Install dependencies
uv sync

# Optional: add Anthropic SDK for Claude models
uv add anthropic
```

## First Run - Setup

Before running any analysis, configure your AI provider:

```bash
uv run PyQualify setup
```

```
  Select a provider:

  1  OpenAI      GPT-4o, GPT-4-turbo, GPT-3.5-turbo, ...
  2  Anthropic   Claude 3.5 Sonnet, Claude 3 Opus, ...
  3  Google      Gemini 2.0 Flash, Gemini 1.5 Pro, ...

  Provider [1/2/3]: 1

  OpenAI API key
  > sk-...

  Model (default: gpt-4o)
  > 

  Configuration saved.
  Provider: OpenAI  |  Model: gpt-4o
```

Configuration is stored in `~/.PyQualify/config.toml`. Sensitive values (API keys) are masked when listed. You can re-run `setup` at any time to switch providers or update your key.

## Quick Start

Run `setup` first, then launch the interactive menu:

```bash
uv run PyQualify setup   # one-time configuration
uv run PyQualify         # interactive mode selector
```

```
  Select analysis mode:

  1  Web     Analyze a website for security, SEO, accessibility & performance
  2  Code    Analyze source code for vulnerabilities, quality & test gaps
  3  API     Analyze REST API endpoints for security & integrity

  Mode [1/2/3]: 1

  Target URL (e.g. https://example.com)
  > https://example.com

  Save HTML dashboard report? [y/N]: y
  HTML output filename [report.html]:

  Output raw JSON to stdout? [y/N]:

  Analyzing web page...
```

You can also pass arguments directly for scripting:

```bash
uv run PyQualify web https://example.com
uv run PyQualify code ./src --html report.html
uv run PyQualify api https://api.example.com --json
```

## Configuration

PyQualify uses a layered configuration system with the following precedence (highest wins):

1. CLI arguments
2. Environment variables (prefixed with `PYQUALIFY_`)
3. Configuration file (`~/.PyQualify/config.toml`)

The `setup` command writes to the config file. You can also manage values manually:

### Setting Configuration

```bash
# Switch model after setup
uv run PyQualify config set model claude-3-5-sonnet-20241022

# List all configuration (sensitive values are masked)
uv run PyQualify config list

# Delete a value
uv run PyQualify config delete api_key

# Open interactive editor
uv run PyQualify config edit
```

### Environment Variables

Any environment variable prefixed with `PYQUALIFY_` is recognized:

```bash
export PYQUALIFY_API_KEY=sk-your-key
export PYQUALIFY_PROVIDER=openai        # openai | anthropic | google
export PYQUALIFY_MODEL=gpt-4o
export PYQUALIFY_TIMEOUT=60
```

### Configuration File

Located at `~/.PyQualify/config.toml`:

```toml
provider = "openai"
api_key  = "sk-your-openai-key"
model    = "gpt-4o"
timeout  = 60
max_retries  = 3
retry_delay  = 2.0
```

## Commands

| Command | Description |
|---------|-------------|
| `PyQualify setup` | **Run first** - configure AI provider and API key |
| `PyQualify web <url>` | Analyze a web page |
| `PyQualify code <path>` | Analyze source code (file or directory) |
| `PyQualify api <base_url>` | Analyze API endpoints |
| `PyQualify config set <key> <value>` | Set a configuration value |
| `PyQualify config list` | List all configuration |
| `PyQualify config delete <key>` | Remove a configuration value |
| `PyQualify config edit` | Open interactive config editor |

### Common Options

| Option | Description |
|--------|-------------|
| `--html <filename>` | Generate an HTML dashboard report |
| `--json` | Output raw JSON to stdout |
| `--version` | Show version |
| `--help` | Show help |

## Output

### CLI Output

Results are displayed with color-coded severity levels:

- CRITICAL - Immediate action required
- HIGH - Should be addressed soon
- MEDIUM - Moderate risk
- LOW - Minor improvement opportunity
- INFO - Informational finding

A summary block shows the overall Score, Grade, and Risk Level before individual issues.

### JSON Output

```json
{
  "score": 72,
  "grade": "C",
  "risk_level": "high",
  "issues": [
    {
      "check": "missing-csp-header",
      "severity": "high",
      "title": "Missing Content-Security-Policy Header",
      "description": "The web server does not include a CSP header...",
      "evidence": "Response headers: {...}",
      "recommendation": "Add CSP header with restrictive directives...",
      "cwe": "CWE-693",
      "owasp": "A05:2021"
    }
  ],
  "summary": "Analysis found 12 issues across security and quality categories...",
  "metadata": {
    "timestamp": "2024-01-15T10:30:00Z",
    "target": "https://example.com",
    "mode": "web"
  }
}
```

### HTML Dashboard

The `--html` option generates a self-contained HTML file with:

- Score gauge, grade badge, and risk level indicator
- Severity breakdown bar chart
- Issues-by-category proportional bars
- Filterable issues table with expandable details
- Executive summary panel
- Top 5 prioritized recommendations

## Scoring

The scoring algorithm starts at 100 and subtracts penalties per issue:

| Severity | Penalty |
|----------|---------|
| CRITICAL | -20 |
| HIGH | -10 |
| MEDIUM | -5 |
| LOW | -2 |
| INFO | 0 |

The score is clamped to 0-100. Letter grades map as:

| Grade | Score Range |
|-------|-------------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

## Architecture

PyQualify follows a layered pipeline architecture:

```
CLI Layer -> Analysis Engine -> AI Engine -> Scoring -> Report Generator
```

Key design decisions:

- **Dependency Injection** - Lightweight custom container for testability
- **Protocol-based interfaces** - All major components implement Python protocols
- **Async I/O** - `httpx.AsyncClient` for all network operations
- **Modular analyzers** - Each analysis mode is an independent module

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=PyQualify --cov-report=html

# Run a specific test file
uv run pytest tests/test_scoring_engine.py

# Add a new dependency
uv add some-package

# Update the lock file
uv lock
```

## Project Structure

```
PyQualify-tool/
    pyproject.toml
    uv.lock
    README.md
    PyQualify/
        __init__.py
        __main__.py
        models.py
        container.py
        utils.py
        cli/
        analyzers/
        ai/
        reporting/
        scoring/
        config/
        logging/
    tests/
```

## Dependencies

- `click` - CLI framework
- `httpx` - Async HTTP client
- `beautifulsoup4` + `lxml` - HTML parsing
- `openai` - LLM integration
- `jinja2` - HTML template rendering

## License

MIT
