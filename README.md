# PyQualify - AI-Powered QA & Security Analysis Tool

<img width="1074" height="538" alt="banner" src="https://github.com/user-attachments/assets/735d5560-90d2-46c9-bdf7-f215e12110f7" />

PyQualify is a command-line tool that performs automated quality assurance and security analysis across three modes: **Web**, **Code**, and **API**. It leverages LLM-based intelligence to classify findings, produce severity ratings, and generate actionable recommendations.

## Features

- **Web Analysis** - Security headers, form CSRF detection, SEO completeness, accessibility compliance, performance signals, broken link detection, CAPTCHA checks, HTTP request smuggling, case-sensitivity bypass detection, JSON hijacking, DOM-based XSS, open redirect, and server version disclosure
- **Code Analysis** - Security vulnerabilities, bug risk detection, code quality metrics, test gap identification, dependency risk assessment, audit log checks, case-sensitivity bypass detection, known CVE detection, and password policy enforcement
- **API Analysis** - Authentication enforcement, response integrity, schema conformance, injection vector testing, rate limiting verification, audit log manipulation, CAPTCHA bypass, HTTP request smuggling, case-sensitivity bypass, JSON hijacking, open redirect, server version disclosure, internal IP leakage, and application-level DoS
- **AI-Powered Classification** - Findings are processed through an LLM for intelligent severity assignment, CWE/OWASP mapping, and contextual recommendations
- **Scoring & Grading** - Numeric score (0-100), letter grade (A-F), and risk level for every analysis run
- **PDF Reports** - Professionally formatted PDF reports saved automatically to `~/Documents/PyQualify/`
- **Tool Filtering** - Enable or disable individual checks per run with `--only` and `--disable`
- **Color-Coded CLI Output** - Severity-based coloring with graceful fallback for terminals without color support
- **Hierarchical Configuration** - TOML config file, environment variables, and CLI arguments with clear precedence
- **Interactive Config Editor** - Nano-like terminal editor for managing configuration

## Requirements

- [uv](https://docs.astral.sh/uv/) - used for Python version management, dependency locking, and running the project
- An API key for one of the supported AI providers:
  - **OpenAI** - GPT-4o, GPT-4-turbo, GPT-3.5-turbo, ...
  - **Anthropic** - Claude 3.5 Sonnet, Claude 3 Opus, ... (`uv add anthropic` required)
  - **Google** - Gemini 2.0 Flash, Gemini 1.5 Pro, ...
  - **Groq** - Llama 3.3 70B, Mixtral 8x7B, ...

## Installation

### Via pip (recommended)

```bash
pip install pyqualify
```

### Via uv

```bash
uv add pyqualify
```

### From source

```bash
git clone <repo-url> pyqualify
cd pyqualify

# Install dependencies
uv sync

# Optional: add Anthropic SDK for Claude models
uv add anthropic
```

## First Run - Setup

Before running any analysis, configure your AI provider:

```bash
uv run pyqualify setup
```

```
  Choose a provider:

  1  OpenAI      GPT-4o, GPT-4-turbo, GPT-3.5-turbo, ...
  2  Anthropic   Claude 3.5 Sonnet, Claude 3 Opus, ...
  3  Google      Gemini 2.0 Flash, Gemini 1.5 Pro, ...
  4  Groq        Llama 3.3 70B, Mixtral 8x7B, ...

  Provider [1/2/3/4]: 1

  OpenAI API key
  > sk-...

  Model (default: gpt-4o)
  >

  ✔ Configuration saved.
  provider   OpenAI  model   gpt-4o
```

Configuration is stored in `~/.pyqualify/config.toml`. Sensitive values (API keys) are masked when listed. You can re-run `setup` at any time to switch providers or update your key.

## Quick Start

Run `setup` first, then launch the interactive menu:

```bash
pyqualify setup   # one-time configuration
pyqualify         # interactive mode selector
```

```
  Select analysis mode:

  1  Web     Analyze a website for security, SEO, accessibility & performance
  2  Code    Analyze source code for vulnerabilities, quality & test gaps
  3  API     Analyze REST API endpoints for security & integrity

  Mode [1/2/3]: 1

  Target URL (e.g. https://example.com)
  > https://example.com

  Save PDF report to Documents/PyQualify/? [Y/n]: y

  Analyzing web page...
```

You can also pass arguments directly for scripting:

```bash
uv run pyqualify web https://example.com
uv run pyqualify code ./src --pdf
uv run pyqualify api https://api.example.com --json
```

## Configuration

PyQualify uses a layered configuration system with the following precedence (highest wins):

1. CLI arguments
2. Environment variables (prefixed with `PYQUALIFY_`)
3. Configuration file (`~/.pyqualify/config.toml`)

The `setup` command writes to the config file. You can also manage values manually:

### Setting Configuration

```bash
# Switch model after setup
uv run pyqualify config set model claude-3-5-sonnet-20241022

# List all configuration (sensitive values are masked)
uv run pyqualify config list

# Open interactive editor (not available on Windows - use config set instead)
uv run pyqualify config edit
```

### Environment Variables

Any environment variable prefixed with `PYQUALIFY_` is recognized:

```bash
export PYQUALIFY_API_KEY=sk-your-key
export PYQUALIFY_PROVIDER=openai        # openai | anthropic | google | groq
export PYQUALIFY_MODEL=gpt-4o
export PYQUALIFY_TIMEOUT=60
export PYQUALIFY_RATE_LIMIT_BURST=50
export PYQUALIFY_RATE_LIMIT_WINDOW=10
```

### Configuration File

Located at `~/.pyqualify/config.toml`:

```toml
provider    = "openai"
api_key     = "sk-your-openai-key"
model       = "gpt-4o"
timeout     = 60
max_retries = 3
retry_delay = 2.0
```

## Commands

| Command | Description |
|---------|-------------|
| `pyqualify setup` | **Run first** - configure AI provider and API key |
| `pyqualify web <url>` | Analyze a web page |
| `pyqualify code <path>` | Analyze source code (file or directory) |
| `pyqualify api <base_url>` | Analyze API endpoints |
| `pyqualify tools [category]` | List available tools for a category |
| `pyqualify config set <key> <value>` | Set a configuration value |
| `pyqualify config list` | List all configuration |
| `pyqualify config edit` | Open interactive config editor |

### Common Options

| Option | Description |
|--------|-------------|
| `--pdf` | Save a PDF report to `~/Documents/PyQualify/` |
| `--json` | Output raw JSON to stdout |
| `--only <tools>` | Run only the specified tools (comma-separated or repeated) |
| `--disable <tools>` | Skip the specified tools (comma-separated or repeated) |
| `--version` | Show version |
| `--help` | Show help |

### Tool Filtering

Each analysis mode has a set of named tools that can be individually enabled or disabled:

```bash
# List all available tools
uv run pyqualify tools

# List tools for a specific mode
uv run pyqualify tools web
uv run pyqualify tools code
uv run pyqualify tools api

# Run only specific tools
uv run pyqualify web https://example.com --only security-headers,seo
uv run pyqualify api https://api.example.com --only authentication,injection

# Skip specific tools
uv run pyqualify code ./src --disable test-gaps,quality
```

#### Web tools

| Tool | Description |
|------|-------------|
| `security-headers` | Check for missing or misconfigured security headers |
| `forms` | Check forms for CSRF tokens and sensitive autocomplete |
| `seo` | Check for missing SEO elements (title, meta, OG tags) |
| `accessibility` | Check accessibility compliance (alt, headings, ARIA, labels) |
| `performance` | Check performance signals (inline scripts, lazy loading, load time) |
| `links` | Verify links for broken URLs and suspicious domains |
| `captcha` | Detect missing or weak CAPTCHA on sensitive forms |
| `smuggling-headers` | Check for Transfer-Encoding/Content-Length co-existence |
| `case-sensitivity` | Check if URL path casing changes bypass access controls |
| `json-hijacking` | Detect JSON hijacking vectors in HTML scripts |
| `open-redirect` | Detect open redirect parameters in forms and links |
| `server-version-disclosure` | Detect server version/technology in response headers |
| `dom-xss` | Detect DOM-based XSS sinks reading from URL fragments or query strings |

#### Code tools

| Tool | Description |
|------|-------------|
| `security` | Detect injection vulnerabilities, hardcoded secrets, insecure patterns |
| `bug-risks` | Detect null dereferences, uncaught exceptions, race conditions |
| `quality` | Detect dead code, duplicated logic, high complexity, magic numbers |
| `test-gaps` | Detect missing tests, weak assertions, untested branches |
| `dependencies` | Detect typosquatting, deprecated packages, wildcard imports |
| `audit-log` | Detect log injection, log suppression, audit log deletion |
| `case-sensitivity` | Detect missing case normalization in auth/routing comparisons |
| `known-vulnerabilities` | Detect imports of packages with known CVEs |
| `password-policy` | Detect weak or missing password policy enforcement |

#### API tools

| Tool | Description |
|------|-------------|
| `authentication` | Test authentication enforcement (no creds, expired/malformed tokens) |
| `response-integrity` | Test for information leakage and status code mismatches |
| `injection` | Test SQL, NoSQL, and command injection via payloads |
| `rate-limiting` | Test rate limiting by sending burst requests |
| `schema-conformance` | Validate response schema consistency across requests |
| `audit-log-manipulation` | Test for log injection via headers/params |
| `captcha-bypass` | Test if auth endpoints work without CAPTCHA |
| `http-request-smuggling` | Test for CL.TE / TE.CL request smuggling |
| `case-sensitivity` | Test for case-sensitive route/auth bypass |
| `json-hijacking` | Test for unprotected top-level JSON arrays |
| `open-redirect` | Test for open redirect via common redirect parameters |
| `server-version-disclosure` | Detect server version/technology in response headers |
| `internal-ip-leakage` | Detect private IP addresses and internal hostnames in responses |
| `application-dos` | Test for missing payload size and JSON depth limits |

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

### PDF Report

The `--pdf` flag generates a professionally formatted PDF saved to `~/Documents/PyQualify/<target>/<timestamp>.pdf`. The report includes:

- Cover page with score, grade, and risk level
- Executive summary from the AI engine
- Severity breakdown
- Full issues table with CWE/OWASP references
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
- **Modular analyzers** - Each analysis mode is an independent module with individually toggleable tools

## Development

```bash
# Install dev dependencies
uv sync --extra dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=pyqualify --cov-report=html

# Run a specific test file
uv run pytest tests/test_scoring_engine.py

# Add a new dependency
uv add some-package

# Update the lock file
uv lock
```

## Project Structure

```
pyqualify/
    pyproject.toml
    uv.lock
    README.md
    pyqualify/
        __init__.py
        __main__.py
        models.py
        container.py
        utils.py
        tool_registry.py
        cli/
        analyzers/
        ai/
        reporting/
        scoring/
        config/
        logging/
    tests/
    docs/
```

## Dependencies

- `click` - CLI framework
- `httpx` - Async HTTP client
- `beautifulsoup4` + `lxml` - HTML parsing
- `openai` - LLM integration (also used for Google Gemini and Groq via compatible API)
- `jinja2` - HTML template rendering
- `reportlab` - PDF report generation

## License

MIT
