# PDF Reports

The `--pdf` flag generates a PDF report and saves it automatically to `~/Documents/PyQualify/`. No output path is required — the filename is derived from the target and the current timestamp.

---

## Generating a Report

```bash
# Web analysis
uv run pyqualify web https://example.com --pdf

# Code analysis
uv run pyqualify code ./src --pdf

# API analysis
uv run pyqualify api https://api.example.com --pdf

# Combine with JSON output
uv run pyqualify web https://example.com --pdf --json
```

The report is written after analysis completes. A confirmation message is printed to stderr:

```
✔ PDF report saved to: /home/user/Documents/PyQualify/example-com/2026-05-18T14-30-00.pdf
```

---

## Output Path

Reports are saved to:

```
~/Documents/PyQualify/<target-slug>/<ISO-timestamp>.pdf
```

- `<target-slug>` is derived from the target URL or path (hostname for URLs, directory name for paths), with special characters replaced by hyphens
- `<ISO-timestamp>` is the UTC time at the start of the analysis run
- The `~/Documents/PyQualify/` directory and any subdirectories are created automatically if they don't exist

---

## Report Contents

### Cover Page

- Tool name and version
- Target URL or path
- Analysis timestamp (UTC)
- Score, grade, and risk level

### Executive Summary

- Free-text summary from the AI engine
- Total issue count broken down by severity

### Overview Panel

- Score gauge (0-100)
- Grade badge (A-F)
- Risk level indicator (CRITICAL / HIGH / MEDIUM / LOW)

### Severity Breakdown

A bar chart showing the count of issues at each severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).

### Issues Table

A full table of all issues with the following columns:

| Column | Content |
|--------|---------|
| Severity | Color-coded label |
| Check | Kebab-case check identifier |
| Title | Short issue title |
| Description | Full explanation |
| Evidence | Observed evidence |
| Recommendation | Remediation steps |
| CWE | CWE identifier, or N/A |
| OWASP | OWASP Top 10 reference, or N/A |

### Top Recommendations

The five highest-priority actionable recommendations, ordered by severity. Deduplicated by check name so the same check doesn't appear twice.

---

## Interactive Mode

When running PyQualify in interactive mode (no subcommand), you are prompted whether to save a PDF report after entering the target:

```
Save PDF report to Documents/PyQualify/? [Y/n]:
```

The default is **yes**.

---

## Viewing the Report

Open the `.pdf` file in any PDF viewer.

```bash
# Windows
start report.pdf

# macOS
open report.pdf

# Linux
xdg-open report.pdf
```
