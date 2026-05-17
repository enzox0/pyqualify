# Contributing to QAAI

Thank you for your interest in contributing. Here's how to get started.

## Development Setup

```bash
git clone https://github.com/enzox0/qaai-tool
cd qaai-tool

# Install all dependencies including dev tools
uv sync --extra dev
```

## Running Tests

```bash
# Run the full test suite
uv run pytest

# Run with coverage
uv run pytest --cov=qaai --cov-report=term-missing

# Run a specific test file
uv run pytest tests/test_scoring_engine.py -v
```

## Making Changes

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Add or update tests to cover your changes
4. Run the test suite and make sure everything passes
5. Open a pull request using the provided template

## Code Style

- Follow existing patterns in the codebase
- Use type annotations on all function signatures
- Keep functions focused — one responsibility per function
- Write docstrings for public classes and methods

## Commit Messages

Use the conventional commits format:

```
feat: add new analysis check
fix: handle timeout in web analyzer
docs: update configuration section in README
test: add edge cases for scoring engine
chore: update dependencies
```

## Reporting Bugs

Open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your OS, Python version, and `uv run qaai --version` output

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) instead.
