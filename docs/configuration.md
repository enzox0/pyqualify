# Configuration

PyQualify uses a layered configuration system. Values are resolved in this order (highest priority wins):

1. CLI arguments
2. Environment variables (`PYQUALIFY_` prefix)
3. Config file (`~/.pyqualify/config.toml`)

## First-Time Setup

Run the interactive setup wizard:

```bash
uv run pyqualify setup
```

This will prompt you to choose a provider, enter your API key, and select a model. The values are saved to `~/.pyqualify/config.toml`.

## Supported Providers

| Provider  | Slug        | Default Model                    | Extra package needed |
|-----------|-------------|----------------------------------|----------------------|
| OpenAI    | `openai`    | `gpt-4o`                         | - (included)         |
| Anthropic | `anthropic` | `claude-3-5-sonnet-20241022`     | `uv add anthropic`   |
| Google    | `google`    | `gemini-2.0-flash`               | - (included)         |
| Groq      | `groq`      | `llama-3.3-70b-versatile`        | - (included)         |

## Config File

Located at `~/.pyqualify/config.toml` (created automatically on first run):

```toml
provider    = "openai"
api_key     = "your-key"
model       = "gpt-4o"
timeout     = 30
max_retries = 3
retry_delay = 2.0
```

The config directory is created with `700` permissions and the file with `600` permissions so only the current user can read it.

## Environment Variables

All `PYQUALIFY_`-prefixed variables are recognized. The prefix is stripped and the key lowercased:

| Variable                      | Description                          | Default          |
|-------------------------------|--------------------------------------|------------------|
| `PYQUALIFY_PROVIDER`          | AI provider slug                     | `openai`         |
| `PYQUALIFY_API_KEY`           | API key for the provider             | -                |
| `PYQUALIFY_MODEL`             | Model name                           | provider default |
| `PYQUALIFY_BASE_URL`          | Custom API base URL                  | provider default |
| `PYQUALIFY_TIMEOUT`           | HTTP request timeout (seconds)       | `30`             |
| `PYQUALIFY_AI_TIMEOUT`        | AI call timeout (seconds)            | `60`             |
| `PYQUALIFY_MAX_RETRIES`       | Retries on AI failure                | `3`              |
| `PYQUALIFY_RETRY_DELAY`       | Delay between retries (seconds)      | `2.0`            |
| `PYQUALIFY_LOG_LEVEL`         | Log level (DEBUG/INFO/WARNING/ERROR) | `WARNING`        |
| `PYQUALIFY_LOG_FILE`          | Path to log file                     | -                |
| `PYQUALIFY_RATE_LIMIT_BURST`  | Requests in the API rate limit test  | `50`             |
| `PYQUALIFY_RATE_LIMIT_WINDOW` | Duration of the burst window (s)     | `10`             |
| `PYQUALIFY_EXTRA_EXTENSIONS`  | Extra file extensions for code scan  | -                |

Copy `.env.example` to `.env` to use environment variables locally.

## Managing Config via CLI

```bash
# View all current values (sensitive values masked)
uv run pyqualify config list

# Set a value
uv run pyqualify config set model gpt-4-turbo

# Open the interactive nano-like editor
uv run pyqualify config edit
```

> **Note:** The `config edit` command uses a curses-based editor. On Windows, curses is not available — use `config set` instead.
