# API Analysis

API analysis tests a REST API base URL for authentication weaknesses, response integrity issues, schema inconsistencies, injection vulnerabilities, and rate limiting gaps.

```bash
uv run pyqualify api https://api.example.com
uv run pyqualify api https://api.example.com --pdf
uv run pyqualify api https://api.example.com --json
uv run pyqualify api https://api.example.com --only authentication,injection
uv run pyqualify api https://api.example.com --disable rate-limiting
```

---

## What Gets Checked

### Authentication

Four token tests are run against the base URL:

| Test | What's sent | Expected response |
|------|-------------|-------------------|
| No credentials | Empty `Authorization` header | 401 or 403 |
| Expired JWT | JWT with `exp` in the past | 401 or 403 |
| Malformed token | Non-JWT string as Bearer token | 401 or 403 |
| Invalid signature | JWT with tampered signature | 401 or 403 |

If any test receives a 2xx response, a finding is raised.

**BOLA (Broken Object Level Authorization)** - three paths are probed without credentials:

- `{base}/users/999999`
- `{base}/accounts/other-user-id`
- `{base}/profile/admin`

A 2xx response on any of these is flagged.

### Response Integrity

Checks the base URL response and several error-triggering paths for information leakage:

| Check | What's detected |
|-------|----------------|
| `stack-trace-exposure` | Stack trace patterns in error responses (`Traceback`, `at java.`, `NullPointerException`, etc.) |
| `db-query-exposure` | SQL fragments in error responses (`SELECT`, `INSERT INTO`, `pg_catalog`, etc.) |
| `file-path-exposure` | Internal paths in error responses (`/usr/`, `/var/`, `C:\\`, `/home/`) |
| `status-code-mismatch` | Error body with 2xx status, or data body with 4xx/5xx status |
| `sensitive-field-exposure` | Response JSON containing fields named `password`, `secret`, `token`, `private_key`, `api_key`, `ssn`, `credit_card` |

Error paths probed: `{base}/nonexistent-path-404`, `{base}/%00`, `{base}/../../../etc/passwd`.

Sensitive field detection recurses into nested objects and checks the first 5 items of arrays.

### Schema Conformance

Three responses are collected from the base URL. The first is used as a reference schema. Subsequent responses are checked for:

- **Type mismatches** - a field that was a `string` in response 1 becomes an `integer` in response 2
- **Unexpected nulls** - a field that was non-null in response 1 is null in response 2

Requires at least 2 successful 2xx responses to run. Skipped silently if the endpoint is unreachable or returns non-JSON.

### Injection

Six payloads per category are sent as query parameters (`?input=<payload>&q=<payload>`):

| Category | Example payloads |
|----------|-----------------|
| SQL | `' OR 1=1--`, `' UNION SELECT NULL,NULL,NULL--`, `1; DROP TABLE users--` |
| NoSQL | `{"$gt":""}`, `{"$ne":null}`, `{"$regex":".*"}` |
| Command | `; ls -la`, `| cat /etc/passwd`, `$(whoami)` |

A finding is raised if:
- The response body contains error indicators (`syntax error`, `mysql`, `command not found`, `/bin/`, `root:`, etc.)
- The response time exceeds the baseline by more than **5 seconds** (time-based injection)

### Rate Limiting

A burst of **50 requests** is sent within a **10-second window** (configurable via `PYQUALIFY_RATE_LIMIT_BURST` and `PYQUALIFY_RATE_LIMIT_WINDOW`).

| Outcome | Finding raised |
|---------|---------------|
| No 429 received after full burst | `missing-rate-limiting` |
| 429 received but no `Retry-After` header | `missing-retry-after-header` |
| 429 received with `Retry-After` | No finding - rate limiting is correctly implemented |

### Audit Log Manipulation

Tests whether log injection is possible via common request headers and query parameters. Sends payloads containing newline characters and ANSI escape sequences to `User-Agent`, `X-Forwarded-For`, and `Referer` headers. A finding is raised if the server reflects the payload back in the response body without sanitization.

### CAPTCHA Bypass

Tests whether authentication-related endpoints (`/login`, `/register`, `/signup`, `/auth`) accept requests without any CAPTCHA token. Checks for the absence of CAPTCHA validation fields in both the request requirements and response bodies.

### HTTP Request Smuggling

Sends requests with conflicting `Transfer-Encoding: chunked` and `Content-Length` headers (CL.TE and TE.CL variants) to detect desync vulnerabilities. Also checks for `Transfer-Encoding` obfuscation (`Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`).

### Case Sensitivity

Tests whether route and authentication checks are case-sensitive by probing paths with mixed casing (e.g. `/Admin`, `/ADMIN`, `/aDmIn`). A 2xx response on a variant that should be protected indicates a potential bypass.

### JSON Hijacking

Tests for unprotected top-level JSON arrays by sending a GET request with an `Accept: application/json` header. A response that begins with `[` without CSRF protection or an `X-Content-Type-Options: nosniff` header is flagged.

### Open Redirect

Tests common redirect parameters (`redirect`, `next`, `url`, `return`, `returnUrl`, `callback`, `goto`) with an external URL payload. A 3xx response pointing to the injected URL is flagged as an open redirect.

### Server Version Disclosure

Checks response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, etc.) for technology names and version strings that aid fingerprinting and targeted attacks.

### Internal IP Leakage

Scans response bodies and headers for private IP address ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x) and internal hostnames (`.internal`, `.local`, `.corp`, `localhost`).

### Application-Level DoS

Tests whether the API enforces payload size and JSON depth limits:

- Sends a request body of 10 MB to check for missing size limits
- Sends a deeply nested JSON object (100 levels) to check for missing depth limits

A 2xx response to either test is flagged.

---

## Timeouts

Each test category runs with a **30-second timeout** (configurable via `PYQUALIFY_TIMEOUT`). If a category times out, a `{category}-timeout` finding is added and the next category continues.

---

## Options

| Option | Description |
|--------|-------------|
| `--pdf` | Save a PDF report to `~/Documents/PyQualify/` |
| `--json` | Output raw JSON to stdout |
| `--only <tools>` | Run only the specified tools (comma-separated or repeated) |
| `--disable <tools>` | Skip the specified tools (comma-separated or repeated) |

Run `pyqualify tools api` to see all available tool names.

---

## Available Tools

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

---

## Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `PYQUALIFY_TIMEOUT` | `30` | Per-category timeout in seconds |
| `PYQUALIFY_RATE_LIMIT_BURST` | `50` | Number of requests in the rate limit burst test |
| `PYQUALIFY_RATE_LIMIT_WINDOW` | `10` | Duration of the burst window in seconds |

---

## Example Output

```
==================================================
  PyQualify Analysis Summary
==================================================
  Score:      60/100
  Grade:      D
  Risk Level: HIGH
==================================================

  Issues Found: 6

  1. [HIGH] Missing Authentication Enforcement
     Check: missing-auth-enforcement
     Endpoint returned 200 without credentials (expected 401 or 403).
     Unauthenticated requests are being accepted.
     -> Enforce authentication on all non-public endpoints. Return 401
        for missing credentials and 403 for insufficient permissions.
     CWE: CWE-306
     OWASP: A01:2021

  2. [HIGH] Missing Rate Limiting
     Check: missing-rate-limiting
     Sent 50 requests in a 10s burst without receiving a 429 status code.
     -> Implement rate limiting and return 429 with a Retry-After header.
     CWE: CWE-770
     OWASP: A04:2021
  ...
```
