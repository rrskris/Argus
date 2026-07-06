"""
Scan PDF report generators (CVE + RBAC).

Takes the finding structures already produced by cve_service / rbac_service
and renders a downloadable PDF for sharing with a team or attaching to a
ticket. Remediation objects are built by remediation.py and attached to
findings at scan time; older persisted scans without one get it built here
on the fly.
"""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

from .remediation import build_remediation

SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#9a3412"),
    "MEDIUM": colors.HexColor("#854d0e"),
    "LOW": colors.HexColor("#1e3a8a"),
    "UNKNOWN": colors.HexColor("#374151"),
}

_styles = getSampleStyleSheet()
_title_style = ParagraphStyle("ArgusTitle", parent=_styles["Title"], fontSize=20)
_h2_style = ParagraphStyle("ArgusH2", parent=_styles["Heading2"], spaceBefore=14)
_body_style = ParagraphStyle("ArgusBody", parent=_styles["BodyText"], fontSize=9, leading=12)
_remediation_style = ParagraphStyle(
    "ArgusRemediation", parent=_styles["BodyText"], fontSize=9, leading=12,
    textColor=colors.HexColor("#065f46"),
)


def _severity_table(breakdown: dict) -> Table:
    sev_rows = [["Severity", "Count"]] + [
        [sev, str(breakdown.get(sev, 0))] for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    ]
    sev_table = Table(sev_rows, colWidths=[2 * inch, 1 * inch])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    return sev_table


def _finding_header_style(severity: str) -> ParagraphStyle:
    return ParagraphStyle(
        f"sev_{severity}", parent=_h2_style,
        textColor=SEVERITY_COLOR.get(severity, colors.black),
    )


def _benchmark_refs_line(remediation: dict) -> str:
    refs = remediation.get("benchmark_refs") or []
    parts = []
    for ref in refs:
        ref_id = f" {ref['id']}" if ref.get("id") else ""
        parts.append(f"{ref.get('benchmark', '')}{ref_id} — {ref.get('title', '')}")
    return "; ".join(parts)


def _append_remediation(story: list, finding: dict) -> None:
    remediation = finding.get("remediation") or build_remediation(finding)
    story.append(Paragraph(f"<b>What to do:</b> {remediation['action']}", _remediation_style))
    story.append(Paragraph(f"<b>Why it matters:</b> {remediation['why_it_matters']}", _body_style))
    refs_line = _benchmark_refs_line(remediation)
    if refs_line:
        story.append(Paragraph(f"<b>Benchmark:</b> {refs_line}", _body_style))
    if remediation.get("compliance_note"):
        story.append(Paragraph(f"<b>Compliance:</b> {remediation['compliance_note']}", _body_style))
    story.append(Paragraph(f"<b>Audit note:</b> {remediation['audit_note']}", _body_style))


def build_cve_scan_pdf(scan: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    story = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("Argus CVE Scan Report", _title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Cluster version: <b>{scan.get('cluster_version', 'unknown')}</b>", _body_style))
    story.append(Paragraph(f"Scanned at: {scan.get('scanned_at', 'unknown')}", _body_style))
    story.append(Paragraph(
        f"CVEs checked: {scan.get('total_cves_checked', 0)} &mdash; "
        f"Affected: {scan.get('affected_count', 0)}", _body_style
    ))
    story.append(Spacer(1, 10))
    story.append(_severity_table(scan.get("severity_breakdown") or {}))
    story.append(Spacer(1, 16))

    # ── Findings ───────────────────────────────────────────────────────────────
    findings = scan.get("findings") or []
    if not findings:
        story.append(Paragraph("No affected CVEs found in this scan.", _body_style))
    else:
        story.append(Paragraph("Findings", _styles["Heading1"]))
        for f in findings:
            severity = f.get("severity", "UNKNOWN")
            cvss = f.get("cvss_score")
            cvss_str = f" &mdash; CVSS {cvss}" if cvss is not None else ""
            score_str = ""
            if f.get("contextual_score") is not None:
                score_str = f" &mdash; Contextual Risk Score {f['contextual_score']}"
            story.append(Paragraph(
                f"[{severity}] {f.get('cve_id', 'UNKNOWN')}{cvss_str}{score_str}",
                _finding_header_style(severity),
            ))
            story.append(Paragraph(f.get("title", ""), _body_style))
            if f.get("description"):
                story.append(Paragraph(f["description"], _body_style))

            affected = f.get("affected") or []
            if affected:
                affected_str = ", ".join(
                    f"{a.get('component')} ({a.get('version')})" for a in affected
                )
                story.append(Paragraph(f"<b>Affected:</b> {affected_str}", _body_style))

            _append_remediation(story, f)

            refs = f.get("references") or []
            if refs:
                ref_str = ", ".join(r.get("url", "") for r in refs if r.get("url"))
                if ref_str:
                    story.append(Paragraph(f"<b>References:</b> {ref_str}", _body_style))

            story.append(Spacer(1, 8))

    doc.build(story)
    return buf.getvalue()


def build_rbac_scan_pdf(scan: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    story = []

    # ── Cover ──────────────────────────────────────────────────────────────────
    story.append(Paragraph("Argus RBAC Scan Report", _title_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Scanned at: {scan.get('scanned_at', 'unknown')}", _body_style))
    story.append(Paragraph(
        f"Bindings checked: {scan.get('total_bindings_checked', 0)} &mdash; "
        f"Findings: {scan.get('affected_count', 0)}", _body_style
    ))
    story.append(Spacer(1, 10))
    story.append(_severity_table(scan.get("severity_breakdown") or {}))
    story.append(Spacer(1, 16))

    # ── Findings ───────────────────────────────────────────────────────────────
    findings = scan.get("findings") or []
    if not findings:
        story.append(Paragraph("No RBAC misconfigurations found in this scan.", _body_style))
    else:
        story.append(Paragraph("Findings", _styles["Heading1"]))
        for f in findings:
            severity = f.get("severity", "UNKNOWN")
            score_str = ""
            if f.get("contextual_score") is not None:
                score_str = f" &mdash; Contextual Risk Score {f['contextual_score']}"
            story.append(Paragraph(
                f"[{severity}] {f.get('title', 'RBAC finding')}{score_str}",
                _finding_header_style(severity),
            ))
            if f.get("description"):
                story.append(Paragraph(f["description"], _body_style))

            binding = f.get("binding") or {}
            binding_str = f"{binding.get('kind', '?')} '{binding.get('name', '?')}'"
            if binding.get("namespace"):
                binding_str += f" (namespace: {binding['namespace']})"
            subjects = f.get("subjects") or []
            subjects_str = ", ".join(
                f"{s.get('kind')}:{s.get('name')}" for s in subjects
            ) or "none"
            story.append(Paragraph(f"<b>Binding:</b> {binding_str}", _body_style))
            story.append(Paragraph(f"<b>Subjects:</b> {subjects_str}", _body_style))

            _append_remediation(story, f)
            story.append(Spacer(1, 8))

    doc.build(story)
    return buf.getvalue()
