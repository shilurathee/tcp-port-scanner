"""SOC Penetration Testing & Reconnaissance Reports: PDF, CSV, and JSON."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# SOC / Cyber Report Color Palette
DARK_HEADER = colors.HexColor("#0f1620")
DARK_ACCENT = colors.HexColor("#1c2a3a")
CYAN_ACCENT = colors.HexColor("#0284c7")
GREEN_ACCENT = colors.HexColor("#059669")
RED_ACCENT = colors.HexColor("#dc2626")
AMBER_ACCENT = colors.HexColor("#d97706")
TEXT_MAIN = colors.HexColor("#0f172a")
TEXT_MUTED = colors.HexColor("#475569")
BG_CARD = colors.HexColor("#f8fafc")
BG_CODE = colors.HexColor("#0a0e14")
TEXT_CODE = colors.HexColor("#00ff9c")
BORDER_LIGHT = colors.HexColor("#cbd5e1")


def _stamp(when: str | None) -> str:
    if when:
        return when
    return datetime.now(timezone.utc).strftime("%d %B %Y, %H:%M UTC")


def summary_line(results: list[dict], total_ports: int, elapsed: float | None = None) -> str:
    opened = len(results)
    timing_str = f" in {elapsed:.2f}s" if (elapsed is not None and elapsed > 0) else ""
    return f"{opened} OPEN / {total_ports} SCANNED{timing_str}"


def build_json(payload: dict) -> bytes:
    body = {
        "report_type": "SOC Port Reconnaissance Report",
        "classification": "CONFIDENTIAL // AUTHORIZED ENGAGEMENT",
        "target": payload["target"],
        "resolved_ip": payload.get("ip"),
        "generated_at": _stamp(payload.get("finished_at")),
        "duration_seconds": payload.get("elapsed"),
        "settings": payload.get("settings", {}),
        "summary": summary_line(
            payload.get("results", []),
            payload.get("total", 0),
            payload.get("elapsed"),
        ),
        "total_scanned": payload.get("total", 0),
        "open_count": len(payload.get("results", [])),
        "equivalent_nmap_command": payload.get("equivalent_command"),
        "findings": payload.get("results", []),
    }
    return json.dumps(body, indent=2).encode("utf-8")


def build_csv(payload: dict) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["# SOC PORT RECONNAISSANCE REPORT"])
    writer.writerow(["target", payload["target"]])
    writer.writerow(["resolved_ip", payload.get("ip", "")])
    writer.writerow(["generated_at", _stamp(payload.get("finished_at"))])
    if payload.get("elapsed"):
        writer.writerow(["duration_seconds", f"{payload.get('elapsed'):.2f}"])
    writer.writerow([
        "summary",
        summary_line(
            payload.get("results", []),
            payload.get("total", 0),
            payload.get("elapsed"),
        ),
    ])
    writer.writerow(["equivalent_nmap", payload.get("equivalent_command", "")])
    writer.writerow([])
    writer.writerow(["port", "protocol", "state", "service", "banner_version"])
    for row in payload.get("results", []):
        writer.writerow([
            row.get("port"),
            "tcp",
            row.get("state", "open"),
            row.get("service", "unknown"),
            row.get("banner", ""),
        ])
    return buf.getvalue().encode("utf-8")


def _draw_pentest_page(canvas, doc) -> None:
    canvas.saveState()
    # Dark SOC top header banner
    banner_height = 1.05 * inch
    canvas.setFillColor(DARK_HEADER)
    canvas.rect(0, letter[1] - banner_height, letter[0], banner_height, fill=1, stroke=0)

    # Accent cyan line under header banner
    canvas.setFillColor(CYAN_ACCENT)
    canvas.rect(0, letter[1] - banner_height, letter[0], 2.5, fill=1, stroke=0)

    # Banner titles
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawString(0.8 * inch, letter[1] - 0.48 * inch, "SECURITY OPERATIONS CENTER // PORT RECONNAISSANCE")

    canvas.setFont("Courier-Bold", 8.5)
    canvas.setFillColor(colors.HexColor("#00ff9c"))
    canvas.drawRightString(letter[0] - 0.8 * inch, letter[1] - 0.48 * inch, "STATUS: COMPLETE")

    canvas.setFont("Helvetica", 8.5)
    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.drawString(0.8 * inch, letter[1] - 0.75 * inch, "ASSESSMENT CLASSIFICATION: CONFIDENTIAL // AUTHORIZED TESTING ONLY")

    # Bottom footer rule and text
    canvas.setStrokeColor(BORDER_LIGHT)
    canvas.setLineWidth(0.6)
    canvas.line(0.8 * inch, 0.7 * inch, letter[0] - 0.8 * inch, 0.7 * inch)

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(
        0.8 * inch,
        0.52 * inch,
        "Scope & Authorization: Scanning conducted strictly within verified testing permissions. Unauthorized use prohibited.",
    )
    canvas.drawRightString(
        letter[0] - 0.8 * inch,
        0.52 * inch,
        f"Page {doc.page}",
    )
    canvas.restoreState()


def build_pdf(payload: dict) -> bytes:
    buf = io.BytesIO()
    target_name = payload.get("target", "Target")
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.8 * inch,
        rightMargin=0.8 * inch,
        topMargin=1.35 * inch,
        bottomMargin=0.95 * inch,
        title=f"SOC Port Reconnaissance — {target_name}",
        author="Security Operations Center",
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=DARK_HEADER,
        spaceBefore=10,
        spaceAfter=4,
    )

    body_style = ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=TEXT_MAIN,
    )

    code_style = ParagraphStyle(
        "CodeLine",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=TEXT_CODE,
    )

    cell_mono = ParagraphStyle(
        "CellMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=10,
        textColor=TEXT_MAIN,
    )

    cell_mono_bold = ParagraphStyle(
        "CellMonoBold",
        parent=cell_mono,
        fontName="Courier-Bold",
    )

    cell_head = ParagraphStyle(
        "CellHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )

    findings = payload.get("results", [])
    total = payload.get("total", 0)
    elapsed = payload.get("elapsed")
    settings = payload.get("settings", {})
    resolved_ip = payload.get("ip", "—")
    gen_time = _stamp(payload.get("finished_at"))

    story = []

    # Section 1: Executive Reconnaissance Metadata
    story.append(Paragraph("1. Target & Reconnaissance Scope", title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceAfter=8))

    meta_table_data = [
        [
            Paragraph("<b>Target Host:</b>", body_style),
            Paragraph(f"<font face='Courier-Bold'>{target_name}</font>", body_style),
            Paragraph("<b>Resolved IPv4:</b>", body_style),
            Paragraph(f"<font face='Courier-Bold'>{resolved_ip}</font>", body_style),
        ],
        [
            Paragraph("<b>Execution Time:</b>", body_style),
            Paragraph(gen_time, body_style),
            Paragraph("<b>Scan Profile:</b>", body_style),
            Paragraph(str(settings.get("ports", "Standard")), body_style),
        ],
        [
            Paragraph("<b>Workers / Concurrency:</b>", body_style),
            Paragraph(f"{settings.get('threads', '—')} threads", body_style),
            Paragraph("<b>Service Detection (-sV):</b>", body_style),
            Paragraph("Active" if settings.get("identify") else "Disabled", body_style),
        ],
    ]
    meta_table = Table(meta_table_data, colWidths=[1.4 * inch, 2.1 * inch, 1.4 * inch, 2.0 * inch])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # Section 2: Command Equivalence
    if payload.get("equivalent_command"):
        cmd_text = f"$ {payload['equivalent_command']}"
        cmd_table = Table(
            [[Paragraph("<b>Nmap Command Equivalence:</b>", body_style)], [Paragraph(cmd_text, code_style)]],
            colWidths=[6.9 * inch],
        )
        cmd_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), BG_CARD),
                    ("BACKGROUND", (0, 1), (-1, 1), BG_CODE),
                    ("BOX", (0, 0), (-1, -1), 0.5, DARK_ACCENT),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(cmd_table)
        story.append(Spacer(1, 10))

    # Section 3: Scan Summary Metric Cards
    story.append(Paragraph("2. Executive Scan Summary", title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceAfter=8))

    open_count = len(findings)
    closed_count = max(0, total - open_count)
    duration_str = f"{elapsed:.2f}s" if (elapsed is not None and elapsed > 0) else "N/A"
    rate_str = f"{int(total / elapsed):,} ports/s" if (elapsed and elapsed > 0) else "N/A"

    summary_data = [
        [
            Paragraph("<b>TOTAL PORTS</b>", cell_head),
            Paragraph("<b>OPEN PORTS</b>", cell_head),
            Paragraph("<b>CLOSED / FILTERED</b>", cell_head),
            Paragraph("<b>SCAN DURATION</b>", cell_head),
            Paragraph("<b>AVERAGE RATE</b>", cell_head),
        ],
        [
            Paragraph(f"<font size='11'><b>{total:,}</b></font>", cell_mono_bold),
            Paragraph(f"<font size='11' color='#059669'><b>{open_count}</b></font>", cell_mono_bold),
            Paragraph(f"<font size='11'><b>{closed_count:,}</b></font>", cell_mono_bold),
            Paragraph(f"<font size='11'><b>{duration_str}</b></font>", cell_mono_bold),
            Paragraph(f"<font size='11'><b>{rate_str}</b></font>", cell_mono_bold),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[1.38 * inch] * 5)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), DARK_HEADER),
                ("BACKGROUND", (0, 1), (-1, 1), BG_CARD),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # Section 4: Detailed Open Ports Table
    story.append(Paragraph("3. Discovered Services & Banners", title_style))
    story.append(HRFlowable(width="100%", thickness=1, color=CYAN_ACCENT, spaceAfter=8))

    findings_data = [
        [
            Paragraph("PORT", cell_head),
            Paragraph("STATE", cell_head),
            Paragraph("SERVICE", cell_head),
            Paragraph("VERSION / BANNER FINGERPRINT", cell_head),
        ]
    ]

    if not findings:
        findings_data.append(
            [
                Paragraph("—", cell_mono),
                Paragraph("NO OPEN PORTS", cell_mono),
                Paragraph("—", cell_mono),
                Paragraph("No answering TCP services were detected across the surveyed range.", cell_mono),
            ]
        )
    else:
        for row in findings:
            port_str = f"{row.get('port')}/tcp"
            state_str = str(row.get("state", "open")).upper()
            service_str = str(row.get("service") or "unknown")
            raw_banner = row.get("banner") or "—"
            safe_banner = raw_banner[:200].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            findings_data.append(
                [
                    Paragraph(f"<b>{port_str}</b>", cell_mono_bold),
                    Paragraph(f"<font color='#059669'><b>{state_str}</b></font>", cell_mono_bold),
                    Paragraph(f"<b>{service_str}</b>", cell_mono),
                    Paragraph(safe_banner, cell_mono),
                ]
            )

    findings_table = Table(findings_data, colWidths=[0.9 * inch, 0.9 * inch, 1.3 * inch, 3.8 * inch])
    findings_style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_HEADER),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]

    # Alternating row coloring for findings
    for i in range(1, len(findings_data)):
        bg = BG_CARD if i % 2 == 1 else colors.white
        findings_style.append(("BACKGROUND", (0, i), (-1, i), bg))

    findings_table.setStyle(TableStyle(findings_style))
    story.append(findings_table)
    story.append(Spacer(1, 14))

    # Section 5: Scope & Authorization Notice
    scope_notice = (
        "<b>Scope & Methodology Notice:</b> This audit utilized multithreaded TCP connect scanning. "
        "Unlike stealth SYN probing, full socket connections were negotiated to ascertain listening services "
        "and extract initial software greeting banners. Results are constrained to the ports examined at the time of execution. "
        "Retain as confidential penetration testing intelligence."
    )
    notice_table = Table(
        [[Paragraph(scope_notice, ParagraphStyle("Notice", parent=body_style, fontSize=7.5, leading=10, textColor=TEXT_MUTED))]],
        colWidths=[6.9 * inch],
    )
    notice_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_LIGHT),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(notice_table)

    doc.build(story, onFirstPage=_draw_pentest_page, onLaterPages=_draw_pentest_page)
    return buf.getvalue()


def write_report(path: Path, payload: dict, fmt: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "pdf":
        data = build_pdf(payload)
    elif fmt == "csv":
        data = build_csv(payload)
    elif fmt == "json":
        data = build_json(payload)
    else:
        raise ValueError(f"unknown report format: {fmt}")
    path.write_bytes(data)
    return path
