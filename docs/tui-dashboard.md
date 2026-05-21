# TUI Dashboard

The `dashboard` command launches a full-screen interactive terminal UI built with [Textual](https://textual.textualize.io/). It provides live metrics, a scrollable issues table, a real-time log feed, and an issue detail panel — all updating as analysis runs.

```bash
# Open the dashboard in idle state
pyqualify dashboard

# Auto-start analysis on launch
pyqualify dashboard web https://example.com
pyqualify dashboard code ./src
pyqualify dashboard api https://api.example.com
```

---

## Requirements

- Terminal of at least **80 columns × 24 rows**. The dashboard exits with code 1 if the terminal is too small and displays an error notification.
- PyQualify must be configured (`pyqualify setup`) before running analysis. The dashboard can still be launched without configuration — it will show a warning and remain in idle state.

---

## Panels

The dashboard is divided into six panels arranged in a CSS grid layout:

### Header

Displays the tool name, version, and three status indicators:

| Indicator | States |
|-----------|--------|
| AI Engine | `● ready` (green) / `○ setup needed` (yellow) |
| Analyzer | `● <mode> analyzer` (green) / `○ no analyzer` (yellow) |
| Analysis | `idle` → `analyzing (N%)` → `● complete` (green) / `✖ <source>` (red) |

The analysis indicator updates in real time as analysis progresses, showing the current phase name and estimated completion percentage.

### Metrics

Shows the live analysis results:

- **Score** — numeric score (0–100) with a progress bar
- **Grade** — letter grade (A–F)
- **Risk Level** — CRITICAL / HIGH / MEDIUM / LOW
- **Issue counts** — per-severity breakdown (CRITICAL, HIGH, MEDIUM, LOW, INFO)

All values update as issues are discovered. A brief highlight effect signals when analysis completes.

### Issues

A scrollable table of all discovered issues, sorted by severity. Columns:

| Column | Content |
|--------|---------|
| Severity | Color-coded label |
| Check | Kebab-case check identifier |
| Title | Short issue title |

Press **Enter** on any row to open the Issue Detail panel.

### Issue Detail

A full-width overlay panel showing the complete details of the selected issue:

- Severity, check name, and title
- Full description
- Evidence
- Recommendation
- CWE and OWASP references

Press **Escape** to close and return focus to the Issues table.

### Log

A live-scrolling log feed showing messages from the analysis engine. Each entry includes a timestamp, log level, and message. Log levels are color-coded:

| Level | Color |
|-------|-------|
| debug | dim |
| info | default |
| warning | yellow |
| error | red |

### Navigation Bar

Displays context-sensitive keyboard shortcut hints at the bottom of the screen. The shortcuts shown change based on which panel currently has focus.

---

## Keyboard Shortcuts

### Global

| Key | Action |
|-----|--------|
| `q` | Quit (exit code 0) |
| `Ctrl+C` | Force quit (exit code 130) |
| `?` | Show help overlay |
| `1` | Focus Metrics panel |
| `2` | Focus Issues panel |
| `3` | Focus Log panel |

### Issues Panel

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `Enter` | Open Issue Detail panel |

### Issue Detail Panel

| Key | Action |
|-----|--------|
| `Escape` | Close and return focus to Issues |

---

## Auto-Start

When both a mode and a target are provided on the command line, analysis begins automatically as soon as the dashboard finishes mounting:

```bash
pyqualify dashboard web https://example.com
```

Without a target, the dashboard opens in idle state and waits. You can initiate analysis from within the dashboard using the keyboard shortcuts shown in the Navigation Bar.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| AI engine not configured | Warning shown; dashboard remains in idle state |
| Analysis fails | Status indicator transitions to `✖ <source>`; error logged to Log panel; dashboard stays open |
| Stalled analysis (no progress for 30s) | Warning logged to Log panel; stall indicator shown in Header |
| Rendering error | Error logged; widget refresh attempted; graceful shutdown after 3 errors within 10 seconds |
| Terminal too small | Error notification shown; exit with code 1 |
| `Ctrl+C` during analysis | Analysis cancelled; exit with code 130 |

---

## Responsive Layout

The dashboard adapts to terminal resize events. All panels reflow their content to fit the new dimensions within one second. Panel borders always remain as closed rectangles and panel titles are always preserved.

If the terminal is resized below the 80×24 minimum, the dashboard exits with code 1.

---

## Implementation Notes

See [Architecture](architecture.md#tui-dashboard---pyqualifytui) for a full breakdown of the TUI module structure, message flow, and component responsibilities.
