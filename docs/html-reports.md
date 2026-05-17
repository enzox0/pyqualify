# HTML Reports

The `--html` flag generates a self-contained HTML dashboard report. The file has all CSS and JavaScript inlined - no internet connection or external assets are needed to view it.

---

## Generating a Report

```bash
# Web analysis
uv run pyqualify web https://example.com --html report.html

# Code analysis
uv run pyqualify code ./src --html report.html

# API analysis
uv run pyqualify api https://api.example.com --html report.html

# Combine with JSON output
uv run pyqualify web https://example.com --html report.html --json
```

The report is written after analysis completes. A confirmation message is printed to stderr:

```
HTML report saved to: report.html
```

---

## Report Contents

### Header

- **Score gauge** - visual arc showing the numeric score (0-100)
- **Grade badge** - letter grade (A-F) with color coding
- **Risk level indicator** - CRITICAL / HIGH / MEDIUM / LOW

### Severity Breakdown

A horizontal bar chart showing the count of issues at each severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).

### Issues by Category

Proportional bars showing which check categories contributed the most issues.

### Top 5 Recommendations

The five highest-priority actionable recommendations, ordered by severity. Deduped by check name so the same check doesn't appear twice.

### Issues Table

A filterable table of all issues with expandable detail rows. Columns:

| Column | Content |
|--------|---------|
| Severity | Color-coded badge |
| Check | Kebab-case check identifier |
| Title | Short issue title |
| Description | Full explanation (expandable) |
| Evidence | Observed evidence (expandable) |
| Recommendation | Remediation steps (expandable) |
| CWE | CWE identifier, or N/A |
| OWASP | OWASP Top 10 reference, or N/A |

### Executive Summary Panel

- Total issue count
- Highest severity present
- Free-text summary from the AI engine

### Metadata

- Timestamp (ISO 8601, UTC)
- Target (URL or path)
- Analysis mode (web / code / api)

---

## Output Path Rules

- The output directory must already exist - PyQualify will not create it
- The filename must be 1-255 characters with no reserved characters (`< > : " / \ | ? *`)
- If the file already exists it will be overwritten (provided it is writable)

---

## Viewing the Report

Open the `.html` file in any modern browser. No server required.

```bash
# Windows
start report.html

# macOS
open report.html

# Linux
xdg-open report.html
```
