# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest  | ✅        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in QAAI, please report it responsibly:

1. Open a [GitHub Security Advisory](https://github.com/enzox0/qaai-tool/security/advisories/new) (preferred)
2. Or email the maintainers directly with a description of the issue

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Any suggested fixes or mitigations

You can expect an acknowledgement within 48 hours and a resolution timeline within 7 days for critical issues.

## Security Considerations When Using QAAI

- **API keys** — QAAI stores your API key in `~/.qaai/config.toml` with owner-only permissions (`0600`). Never commit this file.
- **`.env.example`** — The provided example file contains no real secrets. Copy it to `.env` and fill in your values; `.env` is listed in `.gitignore`.
- **Analysis targets** — QAAI makes HTTP requests to the URLs and APIs you provide. Only analyze targets you own or have explicit permission to test.
- **HTML reports** — Generated reports may contain excerpts of the analyzed content. Treat them as sensitive if the target is sensitive.
