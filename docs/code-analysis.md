# Code Analysis

Code analysis scans a file or directory for security vulnerabilities, bug risks, code quality issues, test gaps, and dependency problems.

```bash
uv run pyqualify code ./src
uv run pyqualify code ./src --html report.html
uv run pyqualify code ./src --json
uv run pyqualify code path/to/single_file.py
```

---

## Supported Languages

Any file with one of these extensions is analyzed:

`.py` `.js` `.ts` `.jsx` `.tsx` `.java` `.rb` `.go` `.php` `.cs` `.cpp` `.c` `.h` `.rs` `.swift` `.kt`

When a directory is given, it is walked recursively. Hidden directories and common non-source directories are skipped automatically: `.git`, `node_modules`, `__pycache__`, `venv`, `.venv`, `dist`, `build`.

---

## What Gets Checked

### Security

| Check | What's detected |
|-------|----------------|
| `sql-injection` | String formatting or f-strings inside `execute()` / `cursor.execute()` / raw SQL keywords |
| `command-injection` | `os.system`, `os.popen`, `subprocess` with `shell=True` or f-string args, `eval`/`exec` with user input |
| `xss-vulnerability` | `innerHTML =`, `document.write`, `.html()` with user input, `dangerouslySetInnerHTML`, `v-html`, `mark_safe` |
| `hardcoded-secret` | API keys, AWS keys, passwords, tokens, private key headers assigned as string literals |
| `insecure-deserialization` | `pickle.loads`, `yaml.load` without `SafeLoader`, `marshal.loads`, `jsonpickle.decode`, Java `ObjectInputStream` |
| `path-traversal` | `open()`, `os.path.join`, `Path()`, `readFile` called with request/input/argv variables |
| `insecure-random` | `random.random/randint/choice` used in security-sensitive contexts (token, secret, session, csrf) |
| `broken-auth-hardcoded-credentials` | Hardcoded usernames/passwords like `admin`, `password`, `123456` |
| `broken-auth-missing-validation` | JWT `verify=False`, `algorithms=["none"]`, `verify_signature=False` |

Secrets found in evidence are automatically redacted (`****REDACTED****`) before being sent to the AI engine.

### Bug Risks

| Check | What's detected |
|-------|----------------|
| `null-dereference` | Chained attribute access on `.get()` returns, `find()`/`search()`/`match()` results used without null check |
| `uncaught-exception` | `raise` statements outside a `try` block, bare `except:` clauses that swallow all errors |
| `race-condition` | `global`/`threading.Thread`/`multiprocessing` usage, shared mutable state patterns, `asyncio.gather` |
| `off-by-one` | `range(..., len(x) + 1)`, `for ... <= len(...)`, `arr[len(arr)]`, boundary comparisons with `.length`/`.size` |

### Code Quality

| Check | What's detected |
|-------|----------------|
| `dead-code` | Unreachable statements after `return`/`break`/`continue`, unused imports (heuristic) |
| `duplicated-logic` | Identical normalized code blocks of 3+ lines appearing more than once |
| `high-complexity` | Functions with cyclomatic complexity > 10 (counts `if`, `elif`, `for`, `while`, `and`, `or`, `except`, ternary, etc.) |
| `magic-number` | Numeric literals other than `0`, `1`, `-1` used inline (excludes constants, imports, function signatures) |

### Test Gaps

| Check | What's detected |
|-------|----------------|
| `missing-test-file` | Source files with no matching test file (`test_<name>.py`, `<name>_test.py`, `<name>.spec`, etc.) |
| `untested-branches` | Files with more than 5 conditional branches flagged for coverage review |
| `missing-edge-case-test` | Null checks, empty input checks, boundary comparisons that likely need dedicated test cases |
| `weak-assertion` | `assertTrue(x)`, bare `assert x`, `toBeTruthy()`, `toBeDefined()` in test files |

### Dependencies

| Check | What's detected |
|-------|----------------|
| `typosquatting-import` | Package names within edit distance 1-2 of popular packages (requests, numpy, flask, django, react, etc.) |
| `deprecated-package` | Imports of known deprecated stdlib modules: `optparse`, `imp`, `distutils`, `asyncore`, `asynchat`, `cgi`, etc. |
| `wildcard-import` | `from x import *` statements |

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
  Score:      55/100
  Grade:      F
  Risk Level: CRITICAL
==================================================

  Issues Found: 12

  1. [CRITICAL] Hardcoded AWS Access Key
     Check: hardcoded-secret
     An AWS access key was found hardcoded in the source file. This exposes
     cloud credentials to anyone with access to the repository.
     -> Remove the key from source code. Use environment variables or a
        secrets manager. Rotate the exposed key immediately.
     CWE: CWE-798
     OWASP: A07:2021

  2. [HIGH] SQL Injection via String Formatting
     Check: sql-injection
     src/db.py:42 - cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
     -> Use parameterized queries: cursor.execute("SELECT ... WHERE id=%s", (user_id,))
     CWE: CWE-89
     OWASP: A03:2021
  ...
```
