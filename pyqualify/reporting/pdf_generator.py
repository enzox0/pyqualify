"""PDF report generator using ReportLab."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from pyqualify.models import AnalysisResult, Issue, Severity

# ── XML escape helper ─────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    """Escape text for ReportLab's XML-based Paragraph parser.

    Replaces &, <, > so that raw HTML/XML in issue descriptions
    doesn't get interpreted as markup.
    """
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )

# ── Colour palette (dark-theme inspired, adapted for print) ──────────────────

_BG_DARK = colors.HexColor("#1a1a2e")
_BG_PANEL = colors.HexColor("#16213e")
_BG_ROW_ALT = colors.HexColor("#f5f7fa")
_ACCENT = colors.HexColor("#64b5f6")
_TEXT_MAIN = colors.HexColor("#1a1a2e")
_TEXT_MUTED = colors.HexColor("#5a6a7a")
_WHITE = colors.white

_SEV_COLORS: dict[str, colors.HexColor] = {
    "critical": colors.HexColor("#dc3545"),
    "high": colors.HexColor("#fd7e14"),
    "medium": colors.HexColor("#e6a817"),
    "low": colors.HexColor("#0d6efd"),
    "info": colors.HexColor("#6c757d"),
}

_GRADE_COLORS: dict[str, colors.HexColor] = {
    "A": colors.HexColor("#28a745"),
    "B": colors.HexColor("#64b5f6"),
    "C": colors.HexColor("#e6a817"),
    "D": colors.HexColor("#fd7e14"),
    "F": colors.HexColor("#dc3545"),
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


# ── Path helpers ──────────────────────────────────────────────────────────────

def resolve_pdf_path(target: str) -> Path:
    """Build the output path: ~/Documents/PyQualify/<slug>/<timestamp>.pdf."""
    docs = Path.home() / "Documents" / "PyQualify"

    # Derive a filesystem-safe slug from the target
    try:
        parsed = urlparse(target)
        slug = parsed.netloc or parsed.path
    except Exception:
        slug = target

    # Strip scheme, replace unsafe chars
    slug = re.sub(r"[^\w\-.]", "_", slug).strip("_.")
    slug = re.sub(r"_+", "_", slug) or "report"

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = docs / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{timestamp}.pdf"


# ── Style helpers ─────────────────────────────────────────────────────────────

def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Normal"],
            fontSize=22,
            leading=28,
            textColor=_WHITE,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#c0d0e0"),
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "section",
            parent=base["Normal"],
            fontSize=13,
            leading=18,
            textColor=_ACCENT,
            fontName="Helvetica-Bold",
            spaceBefore=6,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=_TEXT_MAIN,
            fontName="Helvetica",
        ),
        "body_muted": ParagraphStyle(
            "body_muted",
            parent=base["Normal"],
            fontSize=8,
            leading=12,
            textColor=_TEXT_MUTED,
            fontName="Helvetica",
        ),
        "label": ParagraphStyle(
            "label",
            parent=base["Normal"],
            fontSize=8,
            leading=11,
            textColor=_ACCENT,
            fontName="Helvetica-Bold",
        ),
        "value": ParagraphStyle(
            "value",
            parent=base["Normal"],
            fontSize=8,
            leading=12,
            textColor=_TEXT_MAIN,
            fontName="Helvetica",
            wordWrap="CJK",
        ),
        "score_big": ParagraphStyle(
            "score_big",
            parent=base["Normal"],
            fontSize=36,
            leading=42,
            textColor=_TEXT_MAIN,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "grade_big": ParagraphStyle(
            "grade_big",
            parent=base["Normal"],
            fontSize=36,
            leading=42,
            fontName="Helvetica-Bold",
            alignment=TA_CENTER,
        ),
        "caption": ParagraphStyle(
            "caption",
            parent=base["Normal"],
            fontSize=7,
            leading=10,
            textColor=_TEXT_MUTED,
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "footer",
            parent=base["Normal"],
            fontSize=7,
            leading=10,
            textColor=_TEXT_MUTED,
            fontName="Helvetica",
            alignment=TA_RIGHT,
        ),
        "rec_title": ParagraphStyle(
            "rec_title",
            parent=base["Normal"],
            fontSize=9,
            leading=13,
            textColor=_TEXT_MAIN,
            fontName="Helvetica-Bold",
        ),
        "rec_body": ParagraphStyle(
            "rec_body",
            parent=base["Normal"],
            fontSize=8,
            leading=12,
            textColor=_TEXT_MAIN,
            fontName="Helvetica",
            wordWrap="CJK",
        ),
    }


def _sev_color(severity: str) -> colors.HexColor:
    return _SEV_COLORS.get(severity.lower(), _SEV_COLORS["info"])


def _grade_color(grade: str) -> colors.HexColor:
    return _GRADE_COLORS.get(grade.upper()[:1], _TEXT_MUTED)


# ── Page template (header/footer drawn on every page) ────────────────────────

class _PageTemplate:
    def __init__(self, target: str, timestamp: str) -> None:
        self._target = target
        self._timestamp = timestamp

    def __call__(self, canvas, doc) -> None:  # noqa: ANN001
        canvas.saveState()
        w, h = A4

        # Top bar
        canvas.setFillColor(_BG_DARK)
        canvas.rect(0, h - 14 * mm, w, 14 * mm, fill=1, stroke=0)
        canvas.setFillColor(_ACCENT)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(MARGIN, h - 9 * mm, "PyQualify  ·  AI-Powered QA & Security Analysis")
        canvas.setFillColor(colors.HexColor("#8892b0"))
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - MARGIN, h - 9 * mm, self._target)

        # Bottom bar
        canvas.setFillColor(colors.HexColor("#f0f2f5"))
        canvas.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
        canvas.setFillColor(_TEXT_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(MARGIN, 3.5 * mm, f"Generated: {self._timestamp}")
        canvas.drawRightString(w - MARGIN, 3.5 * mm, f"Page {doc.page}")

        canvas.restoreState()


# ── Main generator ────────────────────────────────────────────────────────────

class PDFReportGenerator:
    """Generates a polished PDF analysis report saved to the user's Documents folder."""

    def generate_pdf_report(self, result: AnalysisResult, output_path: str | Path) -> None:
        """Render the analysis result to a PDF file.

        Args:
            result: The complete analysis result.
            output_path: Destination file path (created by caller).
        """
        output_path = Path(output_path)
        s = _styles()

        timestamp_display = result.metadata.timestamp.replace("T", "  ").split("+")[0].split(".")[0]
        page_cb = _PageTemplate(result.metadata.target, timestamp_display)

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=18 * mm,
            bottomMargin=14 * mm,
            title=f"PyQualify Report – {result.metadata.target}",
            author="PyQualify",
        )

        story: list = []

        story += self._cover(result, s, timestamp_display)
        story.append(PageBreak())
        story += self._executive_summary(result, s)
        story += self._overview_panel(result, s)
        story += self._severity_breakdown(result, s)
        story += self._issues_table(result, s)
        story += self._recommendations(result, s)

        doc.build(story, onFirstPage=page_cb, onLaterPages=page_cb)

    # ── Sections ──────────────────────────────────────────────────────────────

    def _cover(self, result: AnalysisResult, s: dict, ts: str) -> list:
        """Full cover page."""
        items: list = []
        items.append(Spacer(1, 30 * mm))

        # Dark header block
        grade_color = _grade_color(result.grade)
        cover_data = [[
            Paragraph("PyQualify", s["title"]),
        ]]
        cover_table = Table(cover_data, colWidths=[PAGE_W - 2 * MARGIN])
        cover_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _BG_DARK),
            ("TOPPADDING", (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("ROUNDEDCORNERS", [6, 6, 6, 6]),
        ]))
        items.append(cover_table)
        items.append(Spacer(1, 4 * mm))
        items.append(Paragraph("AI-Powered QA &amp; Security Analysis Report", s["subtitle"]))
        items.append(Spacer(1, 12 * mm))

        # Score / Grade / Risk row
        sev_col = _sev_color(result.risk_level.value)
        score_p = Paragraph(str(result.score), s["score_big"])
        grade_p = Paragraph(
            f'<font color="{grade_color.hexval()}"><b>{result.grade}</b></font>',
            s["grade_big"],
        )
        risk_p = Paragraph(
            f'<font color="{sev_col.hexval()}"><b>{result.risk_level.value.upper()}</b></font>',
            s["grade_big"],
        )

        score_cap = Paragraph("Score", s["caption"])
        grade_cap = Paragraph("Grade", s["caption"])
        risk_cap = Paragraph("Risk Level", s["caption"])

        metrics_data = [
            [score_p, grade_p, risk_p],
            [score_cap, grade_cap, risk_cap],
        ]
        col_w = (PAGE_W - 2 * MARGIN) / 3
        metrics_table = Table(metrics_data, colWidths=[col_w] * 3)
        metrics_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f7fa")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 1), (-1, 1), 0),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 12),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, colors.HexColor("#dde3ea")),
            ("LINEBEFORE", (1, 0), (1, -1), 0.5, colors.HexColor("#dde3ea")),
            ("LINEBEFORE", (2, 0), (2, -1), 0.5, colors.HexColor("#dde3ea")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
        ]))
        items.append(metrics_table)
        items.append(Spacer(1, 10 * mm))

        # Target / mode / timestamp
        meta_data = [
            [Paragraph("Target", s["label"]), Paragraph(_esc(result.metadata.target), s["body"])],
            [Paragraph("Mode", s["label"]), Paragraph(result.metadata.mode.value.upper(), s["body"])],
            [Paragraph("Generated", s["label"]), Paragraph(ts, s["body"])],
            [Paragraph("Total Issues", s["label"]), Paragraph(str(len(result.issues)), s["body"])],
        ]
        meta_table = Table(meta_data, colWidths=[35 * mm, PAGE_W - 2 * MARGIN - 35 * mm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f7fa")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#dde3ea")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        items.append(meta_table)
        return items

    def _executive_summary(self, result: AnalysisResult, s: dict) -> list:
        items: list = []
        items.append(Paragraph("Executive Summary", s["section"]))
        items.append(HRFlowable(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=4))
        items.append(Paragraph(_esc(result.summary), s["body"]))
        items.append(Spacer(1, 6 * mm))
        return items

    def _overview_panel(self, result: AnalysisResult, s: dict) -> list:
        items: list = []
        items.append(Paragraph("Overview", s["section"]))
        items.append(HRFlowable(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=4))

        sev_counts: dict[str, int] = {sv: 0 for sv in _SEVERITY_ORDER}
        for issue in result.issues:
            sev_counts[issue.severity.value] = sev_counts.get(issue.severity.value, 0) + 1

        rows = [
            [
                Paragraph("<b>Severity</b>", s["label"]),
                Paragraph("<b>Count</b>", s["label"]),
                Paragraph("<b>Bar</b>", s["label"]),
            ]
        ]
        max_count = max(sev_counts.values(), default=1) or 1
        bar_col_w = 80 * mm
        for sv in _SEVERITY_ORDER:
            cnt = sev_counts[sv]
            bar_w = int(bar_col_w * cnt / max_count) if cnt else 0
            col = _sev_color(sv)
            bar_cell = Table(
                [[" "]],
                colWidths=[bar_w if bar_w else 1],
                rowHeights=[5 * mm],
            )
            bar_cell.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), col if cnt else colors.HexColor("#e0e0e0")),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]))
            rows.append([
                Paragraph(f'<font color="{col.hexval()}"><b>{sv.capitalize()}</b></font>', s["body"]),
                Paragraph(str(cnt), s["body"]),
                bar_cell,
            ])

        col_w = PAGE_W - 2 * MARGIN
        tbl = Table(rows, colWidths=[30 * mm, 20 * mm, col_w - 50 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _BG_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _BG_ROW_ALT]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dde3ea")),
        ]))
        items.append(tbl)
        items.append(Spacer(1, 6 * mm))
        return items

    def _severity_breakdown(self, result: AnalysisResult, s: dict) -> list:
        """Issues grouped by severity as collapsible-style blocks."""
        if not result.issues:
            return []

        items: list = []
        items.append(Paragraph("Issues by Severity", s["section"]))
        items.append(HRFlowable(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=4))

        by_severity: dict[str, list[Issue]] = {sv: [] for sv in _SEVERITY_ORDER}
        for issue in result.issues:
            by_severity[issue.severity.value].append(issue)

        for sv in _SEVERITY_ORDER:
            group = by_severity[sv]
            if not group:
                continue
            col = _sev_color(sv)
            header = Table(
                [[Paragraph(
                    f'<font color="white"><b>{sv.upper()}  ({len(group)})</b></font>',
                    s["body"],
                )]],
                colWidths=[PAGE_W - 2 * MARGIN],
            )
            header.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), col),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            items.append(header)
            for issue in group:
                items.append(self._issue_block(issue, s))
            items.append(Spacer(1, 3 * mm))

        return items

    def _issue_block(self, issue: Issue, s: dict) -> Table:
        """Render a single issue as a detail block."""
        col = _sev_color(issue.severity.value)
        col_w = PAGE_W - 2 * MARGIN

        def row(label: str, value: str) -> list:
            return [
                Paragraph(label, s["label"]),
                Paragraph(_esc(value) if value else "—", s["value"]),
            ]

        detail_rows = [
            row("Title", issue.title),
            row("Check", issue.check),
            row("Description", issue.description),
            row("Evidence", issue.evidence),
            row("Recommendation", issue.recommendation),
        ]
        if issue.cwe:
            detail_rows.append(row("CWE", issue.cwe))
        if issue.owasp:
            detail_rows.append(row("OWASP", issue.owasp))

        detail_tbl = Table(detail_rows, colWidths=[28 * mm, col_w - 28 * mm - 4 * mm])
        detail_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _BG_ROW_ALT]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (0, -1), 6),
            ("LEFTPADDING", (1, 0), (1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEAFTER", (0, 0), (0, -1), 0.5, col),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
        ]))

        wrapper = Table([[detail_tbl]], colWidths=[col_w])
        wrapper.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return KeepTogether([wrapper])

    def _issues_table(self, result: AnalysisResult, s: dict) -> list:
        """Compact summary table of all issues."""
        if not result.issues:
            return []

        items: list = []
        items.append(Paragraph("All Issues — Summary", s["section"]))
        items.append(HRFlowable(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=4))

        col_w = PAGE_W - 2 * MARGIN
        header_row = [
            Paragraph("<b>#</b>", s["label"]),
            Paragraph("<b>Severity</b>", s["label"]),
            Paragraph("<b>Check</b>", s["label"]),
            Paragraph("<b>Title</b>", s["label"]),
        ]
        rows = [header_row]

        sorted_issues = sorted(
            result.issues,
            key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
            if x.severity.value in _SEVERITY_ORDER else 99,
        )

        for i, issue in enumerate(sorted_issues, 1):
            col = _sev_color(issue.severity.value)
            rows.append([
                Paragraph(str(i), s["body_muted"]),
                Paragraph(
                    f'<font color="{col.hexval()}"><b>{issue.severity.value.upper()}</b></font>',
                    s["body"],
                ),
                Paragraph(_esc(issue.check), s["body_muted"]),
                Paragraph(_esc(issue.title), s["body"]),
            ])

        tbl = Table(
            rows,
            colWidths=[10 * mm, 22 * mm, 45 * mm, col_w - 77 * mm],
        )
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _BG_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), _WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _BG_ROW_ALT]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dde3ea")),
        ]))
        items.append(tbl)
        items.append(Spacer(1, 6 * mm))
        return items

    def _recommendations(self, result: AnalysisResult, s: dict) -> list:
        """Top recommendations section."""
        if not result.issues:
            return []

        items: list = []
        items.append(Paragraph("Top Recommendations", s["section"]))
        items.append(HRFlowable(width="100%", thickness=0.5, color=_ACCENT, spaceAfter=6))

        severity_priority = {sv: i for i, sv in enumerate(_SEVERITY_ORDER)}
        sorted_issues = sorted(
            result.issues,
            key=lambda x: severity_priority.get(x.severity.value, 99),
        )

        seen: set[str] = set()
        top: list[Issue] = []
        for issue in sorted_issues:
            if issue.check not in seen:
                seen.add(issue.check)
                top.append(issue)
            if len(top) >= 5:
                break

        col_w = PAGE_W - 2 * MARGIN
        for idx, issue in enumerate(top, 1):
            col = _sev_color(issue.severity.value)
            block_data = [[
                Paragraph(
                    f'<font color="{col.hexval()}"><b>{idx}. {_esc(issue.title)}</b></font>',
                    s["rec_title"],
                ),
            ], [
                Paragraph(_esc(issue.recommendation), s["rec_body"]),
            ], [
                Paragraph(
                    f'<font color="{col.hexval()}">{issue.severity.value.upper()}</font>'
                    + (f'  ·  CWE: {_esc(issue.cwe)}' if issue.cwe else '')
                    + (f'  ·  OWASP: {_esc(issue.owasp)}' if issue.owasp else ''),
                    s["body_muted"],
                ),
            ]]
            block = Table(block_data, colWidths=[col_w - 8 * mm])
            block.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("LINEBEFORE", (0, 0), (0, -1), 4, col),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#dde3ea")),
            ]))
            items.append(KeepTogether([block, Spacer(1, 3 * mm)]))

        return items
