# Configuration

PyQualify uses a layered configuration system. Values are resolved in this order (highest priority wins):

1. CLI arguments
2. Environment variables (`PYQUALIFY_` prefix)
3. Config file (`~/.PyQualify/config.toml`)

## First-Time Setup

Run the interactive setup wizard:

```bash
uv run PyQualify setup
```

This will prompt you to choose a provider, enter your API key, and select a model. The values are saved to `~/.PyQualify/config.toml`.

## Supported Providers

| Provider  | Slug        | Default Model                    | Extra package needed |
|-----------|-------------|----------------------------------|----------------------|
| OpenAI    | `openai`    | `gpt-4o`                         | - (included)         |
| Anthropic | `anthropic` | `claude-3-5-sonnet-20241022`     | `uv add anthropic`   |
| Google    | `google`    | `gemini-2.0-flash`               | - (included)         |

## Config File

Located at `~/.PyQualify/config.toml` (created automatically on first run):

```toml
provider    = "openai"
api_key     = "your-key"
model       = "gpt-4o"
timeout     = 30
max_retries = 3
retry_delay = 2.0
```

## Environment Variables

All `PYQUALIFY_`-prefixed variables are recognized. The prefix is stripped and the key lowercased:

| Variable                | Description                          | Default          |
|-------------------------|--------------------------------------|------------------|
| `PYQUALIFY_PROVIDER`    | AI provider slug                     | `openai`         |
| `PYQUALIFY_API_KEY`     | API key for the provider             | -                |
| `PYQUALIFY_MODEL`       | Model name                           | provider default |
| `PYQUALIFY_BASE_URL`    | Custom API base URL                  | provider default |
| `PYQUALIFY_TIMEOUT`     | HTTP request timeout (seconds)       | `30`             |
| `PYQUALIFY_AI_TIMEOUT`  | AI call timeout (seconds)            | `60`             |
| `PYQUALIFY_MAX_RETRIES` | Retries on AI failure                | `3`              |
| `PYQUALIFY_RETRY_DELAY` | Delay between retries (seconds)      | `2.0`            |
| `PYQUALIFY_LOG_LEVEL`   | Log level (DEBUG/INFO/WARNING/ERROR) | `WARNING`        |
| `PYQUALIFY_LOG_FILE`    | Path to log file                     | -                |

Copy `.env.example` to `.env` to use environment variables locally.

## Managing Config via CLI

```bash
# View all current values (sensitive values masked)
uv run PyQualify config list

# Set a value
uv run PyQualify config set model gpt-4-turbo

# Delete a value
uv run PyQualify config delete model

# Open the interactive nano-like editor
uv run PyQualify config edit
```
