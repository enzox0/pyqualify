# Web Analysis

Web analysis checks a target URL for security, SEO, accessibility, and performance issues.

```bash
uv run pyqualify web https://example.com
uv run pyqualify web https://example.com --html report.html
uv run pyqualify web https://example.com --json
```

---

## What Gets Checked

### Security Headers

Checks for the presence and correct configuration of five headers:

| Header | Severity if missing | Misconfiguration detected |
|--------|--------------------|-----------------------------|
| `Content-Security-Policy` | HIGH | `unsafe-inline`, `unsafe-eval` |
| `Strict-Transport-Security` | HIGH | `max-age` below 31,536,000 (1 year) |
| `X-Frame-Options` | MEDIUM | Value set to `ALLOWALL` |
| `Referrer-Policy` | MEDIUM | - |
| `Permissions-Policy` | MEDIUM | Wildcard `=*` grants |

### Form Security (CSRF)

For every `<form>` with a state-changing method (`POST`, `PUT`, `PATCH`, `DELETE`):

- Checks for a hidden CSRF token input (names: `csrf_token`, `_token`, `authenticity_token`, `csrfmiddlewaretoken`)
- Checks for a CSRF meta tag in `<head>`
- Checks sensitive input fields (`password`, `cc-number`, `cvv`, `ssn`, etc.) for `autocomplete="off"`

GET forms are skipped - they don't require CSRF protection.

### SEO

| Check | What's verified |
|-------|----------------|
| `<title>` tag | Present and non-empty |
| Meta description | `<meta name="description">` with non-empty content |
| Canonical link | `<link rel="canonical">` present |
| Open Graph tags | `og:title`, `og:description`, `og:image`, `og:url` |
| Robots meta | `<meta name="robots">` present |

### Accessibility

| Check | What's verified |
|-------|----------------|
| Image alt attributes | All `<img>` elements have an `alt` attribute |
| Heading hierarchy | No heading level skips (e.g. h1 -> h3) |
| Language attribute | `<html lang="...">` present |
| ARIA roles | Interactive inputs without implicit roles have `role` attribute |
| Form labels | All visible inputs have an associated `<label>` or `aria-label` |

### Performance

| Check | Threshold |
|-------|-----------|
| Inline script size | Flagged if any inline `<script>` exceeds 1 KB |
| Lazy loading | Images beyond the 3rd in document order without `loading="lazy"` |
| Page load time | Flagged if load time exceeds 3,000 ms |

### Links

Up to 500 unique links are verified:

- **Broken links** - 4xx responses flagged as MEDIUM, 5xx as HIGH
- **Timed-out links** - 5-second timeout per request, flagged as LOW
- **Suspicious domains** - homoglyph substitution detection against known brand names (Google, PayPal, GitHub, etc.)

Link checks run concurrently in batches of 20.

---

## Options

| Option | Description |
|--------|-------------|
| `--html <file>` | Write an HTML dashboard report |
| `--json` | Output raw JSON to stdout |

---

## Example Output

```
==================================================
  PyQualify Analysis Summary
==================================================
  Score:      68/100
  Grade:      D
  Risk Level: HIGH
==================================================

  Issues Found: 8

  1. [HIGH] Missing Content-Security-Policy Header
     Check: missing-content-security-policy-header
     The server does not include a CSP header, leaving the page vulnerable
     to cross-site scripting attacks.
     -> Add a Content-Security-Policy header with restrictive directives.
     CWE: CWE-693
     OWASP: A05:2021
  ...
```
