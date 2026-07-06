"""
CVE scan PDF report generator.

Takes the finding structure already produced by cve_service (get_latest_scan /
scan_cluster — scanned_at, cluster_version, severity_breakdown, findings[]) and
renders a downloadable PDF for sharing with a team or attaching to a ticket.
"""

import io
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

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


# Generic patch-management control reference per compliance framework — a
# starting point, not a full compliance-mapping engine (that's future scope).
_COMPLIANCE_CONTROL_NOTES = {
    "PCI-DSS": "PCI-DSS Req 6.2 — apply security patches for known vulnerabilities.",
    "HIPAA": "HIPAA Security Rule 164.308(a)(5) — protect against known vulnerabilities.",
    "SOC2": "SOC 2 CC7.1 — identify and remediate vulnerabilities in a timely manner.",
}


def _action_line(finding: dict) -> str:
    fixed_in = finding.get("fixed_in")
    fixed_version = fixed_in[0] if isinstance(fixed_in, list) and fixed_in else fixed_in
    affected = finding.get("affected") or []
    component = affected[0].get("component") if affected else "the affected component"
    if fixed_version:
        return f"Upgrade {component} to {fixed_version} or later."
    return f"No fixed version published yet for {component} — track this CVE for an update."


def _build_remediation(finding: dict) -> dict:
    """
    Turn a finding's score_factors into the explainable "why + what to do"
    output that's the actual differentiator — not just an upgrade command.
    """
    factors = finding.get("score_factors") or {}
    action = _action_line(finding)

    # Only cite factors that actually raised the score above baseline (weight > 1.0)
    reasons = []
    env = factors.get("environment", {})
    if env.get("weight", 1.0) > 1.0:
        reasons.append(f"this is a {env.get('value')} environment")
    data_class = factors.get("data_classification", {})
    if data_class.get("weight", 1.0) > 1.0:
        reasons.append(f"it handles {data_class.get('value')} data")
    exposure = factors.get("exposure", {})
    if exposure.get("weight", 1.0) > 1.0:
        reasons.append(f"it's {exposure.get('value')}")
    compliance_scope = factors.get("compliance_scope", {}).get("value") or []
    if compliance_scope:
        reasons.append(f"it's in scope for {', '.join(compliance_scope)}")

    score = finding.get("contextual_score")
    if reasons:
        why_it_matters = (
            f"Ranked {score} because {', and '.join(reasons)} — "
            "higher than raw CVSS alone would suggest."
        )
    else:
        why_it_matters = (
            f"Ranked {score}, using baseline severity only — no elevated risk "
            "context (environment, data classification, exposure) is set for this cluster. "
            "Configure it under Settings for sharper prioritization."
        )

    compliance_note = None
    if compliance_scope:
        notes = [_COMPLIANCE_CONTROL_NOTES.get(fw) for fw in compliance_scope]
        compliance_note = " ".join(n for n in notes if n) or None

    audit_note = (
        f"Document remediation of {finding.get('cve_id', 'this CVE')} as evidence "
        f"for {', '.join(compliance_scope)} audit scope." if compliance_scope
        else f"Document remediation of {finding.get('cve_id', 'this CVE')} in your change log."
    )

    return {
        "action": action,
        "why_it_matters": why_it_matters,
        "compliance_note": compliance_note,
        "audit_note": audit_note,
    }


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

    breakdown = scan.get("severity_breakdown") or {}
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
    story.append(sev_table)
    story.append(Spacer(1, 16))

    # ── Findings ───────────────────────────────────────────────────────────────
    findings = scan.get("findings") or []
    if not findings:
        story.append(Paragraph("No affected CVEs found in this scan.", _body_style))
    else:
        story.append(Paragraph("Findings", _styles["Heading1"]))
        for f in findings:
            severity = f.get("severity", "UNKNOWN")
            header_style = ParagraphStyle(
                f"sev_{severity}", parent=_h2_style,
                textColor=SEVERITY_COLOR.get(severity, colors.black),
            )
            cvss = f.get("cvss_score")
            cvss_str = f" &mdash; CVSS {cvss}" if cvss is not None else ""
            score_str = ""
            if f.get("contextual_score") is not None:
                score_str = f" &mdash; Contextual Risk Score {f['contextual_score']}"
            story.append(Paragraph(
                f"[{severity}] {f.get('cve_id', 'UNKNOWN')}{cvss_str}{score_str}", header_style
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

            remediation = _build_remediation(f)
            story.append(Paragraph(f"<b>What to do:</b> {remediation['action']}", _remediation_style))
            story.append(Paragraph(f"<b>Why it matters:</b> {remediation['why_it_matters']}", _body_style))
            if remediation["compliance_note"]:
                story.append(Paragraph(f"<b>Compliance:</b> {remediation['compliance_note']}", _body_style))
            story.append(Paragraph(f"<b>Audit note:</b> {remediation['audit_note']}", _body_style))

            refs = f.get("references") or []
            if refs:
                ref_str = ", ".join(r.get("url", "") for r in refs if r.get("url"))
                if ref_str:
                    story.append(Paragraph(f"<b>References:</b> {ref_str}", _body_style))

            story.append(Spacer(1, 8))

    doc.build(story)
    return buf.getvalue()
