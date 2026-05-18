# Web Analysis

Web analysis checks a target URL for security, SEO, accessibility, and performance issues.

```bash
uv run pyqualify web https://example.com
uv run pyqualify web https://example.com --pdf
uv run pyqualify web https://example.com --json
uv run pyqualify web https://example.com --only security-headers,seo
uv run pyqualify web https://example.com --disable links
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

### CAPTCHA

Detects sensitive forms (login, register, contact, password reset) that lack any CAPTCHA or bot-protection mechanism. Checks for common CAPTCHA providers (reCAPTCHA, hCaptcha, Turnstile, etc.) and `data-sitekey` attributes.

### HTTP Request Smuggling

Checks response headers for co-existence of `Transfer-Encoding` and `Content-Length`, which can enable CL.TE or TE.CL smuggling attacks.

### Case Sensitivity

Probes whether URL path casing changes (e.g. `/Admin` vs `/admin`) return different responses, which may indicate access control bypass vectors.

### JSON Hijacking

Detects inline `<script>` tags that load JSON from external URLs without CSRF protection, which can expose data to cross-origin attackers.

### Open Redirect

Scans form actions and link `href` attributes for common redirect parameters (`redirect`, `next`, `url`, `return`, etc.) that could be abused for phishing.

### Server Version Disclosure

Checks response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, etc.) for technology names and version strings that aid fingerprinting.

### DOM-Based XSS

Detects inline `<script>` blocks that read from `location.hash`, `location.search`, or `document.URL` and write to dangerous sinks (`innerHTML`, `document.write`, `eval`, etc.).

---

## Options

| Option | Description |
|--------|-------------|
| `--pdf` | Save a PDF report to `~/Documents/PyQualify/` |
| `--json` | Output raw JSON to stdout |
| `--only <tools>` | Run only the specified tools (comma-separated or repeated) |
| `--disable <tools>` | Skip the specified tools (comma-separated or repeated) |

Run `pyqualify tools web` to see all available tool names.

---

## Available Tools

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
