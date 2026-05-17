# Scoring

Every analysis run produces three output values: a numeric **score**, a **letter grade**, and a **risk level**. All three are derived from the list of issues returned by the AI engine.

---

## Score

The score starts at **100** and subtracts a penalty for each issue based on its severity:

| Severity | Penalty |
|----------|---------|
| CRITICAL | -20 |
| HIGH     | -10 |
| MEDIUM   | -5  |
| LOW      | -2  |
| INFO     | 0   |

The result is clamped to the range **0-100**. It can never go negative.

**Examples:**

| Issues | Calculation | Score |
|--------|-------------|-------|
| None | 100 | 100 |
| 1 HIGH | 100 - 10 | 90 |
| 1 CRITICAL + 1 HIGH + 1 MEDIUM | 100 - 20 - 10 - 5 | 65 |
| 6 CRITICAL | 100 - 120 -> clamped | 0 |

---

## Grade

The letter grade maps directly from the numeric score:

| Grade | Score Range |
|-------|-------------|
| A | 90 - 100 |
| B | 80 - 89  |
| C | 70 - 79  |
| D | 60 - 69  |
| F | 0 - 59   |

---

## Risk Level

The risk level reflects the **highest severity** present in the issue list, regardless of count:

| Condition | Risk Level |
|-----------|-----------|
| Any CRITICAL issue | `critical` |
| Any HIGH issue (no CRITICAL) | `high` |
| Any MEDIUM issue (no CRITICAL/HIGH) | `medium` |
| Only LOW or INFO issues, or no issues | `low` |

A single CRITICAL issue sets the risk level to `critical` even if the score is otherwise high.

---

## In the Output

### CLI

```
==================================================
  PyQualify Analysis Summary
==================================================
  Score:      72/100
  Grade:      C
  Risk Level: HIGH
==================================================
```

### JSON (`--json`)

```json
{
  "score": 72,
  "grade": "C",
  "risk_level": "high",
  "issues": [...],
  "summary": "...",
  "metadata": {...}
}
```

### HTML Dashboard

The score is shown as a gauge, the grade as a badge, and the risk level as a color-coded indicator at the top of the report. See [HTML Reports](html-reports.md) for details.
