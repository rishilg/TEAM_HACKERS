"""Executive and audit-ready reporting helpers."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_executive_report(events: pd.DataFrame, output_dir: str | Path) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    critical = int((events["priority_level"] == "CRITICAL").sum())
    high = int((events["priority_level"] == "HIGH").sum())
    anomalies = int(events["anomaly_flag"].sum())
    top_controls = events["control_type"].value_counts().head(5)
    mappings = {}
    for values in events["compliance_mappings"]:
        for mapping in values if isinstance(values, list) else []:
            mappings[mapping] = mappings.get(mapping, 0) + 1

    lines = [
        "# Security Drift Intelligence - Executive Audit Report",
        "",
        f"- Events assessed: {len(events)}",
        f"- Critical priorities: {critical}",
        f"- High priorities: {high}",
        f"- Behavioral anomalies: {anomalies}",
        f"- Mean priority score: {events['priority_score'].mean():.1f}",
        "",
        "## Highest-Risk Control Domains",
        "",
    ]
    lines.extend(f"- {name}: {count}" for name, count in top_controls.items())
    lines.extend(["", "## Compliance Exposure", ""])
    lines.extend(f"- {name}: {count} alerts" for name, count in sorted(mappings.items()))
    lines.extend(
        [
            "",
            "## Management Assessment",
            "",
            "Critical and high-priority drift should be reviewed against change approvals and "
            "restored to baseline unless an accepted, time-bound risk exception exists. Behavioral "
            "anomalies are investigative leads, not independent evidence of compromise.",
        ]
    )
    path = output / "executive_audit_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def generate_executive_report_pdf(events: pd.DataFrame, output_dir: str | Path) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / "executive_audit_report.pdf"
    doc = SimpleDocTemplate(str(path), pagesize=landscape(letter), rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    heading = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        spaceAfter=12,
        textColor=colors.HexColor("#0b2340"),
    )
    normal = styles["BodyText"]
    normal.spaceAfter = 8

    critical = int((events["priority_level"] == "CRITICAL").sum())
    high = int((events["priority_level"] == "HIGH").sum())
    anomalies = int(events["anomaly_flag"].sum())
    top_controls = events["control_type"].value_counts().head(5)
    mappings = {}
    for values in events["compliance_mappings"]:
        for mapping in values if isinstance(values, list) else []:
            mappings[mapping] = mappings.get(mapping, 0) + 1

    summary_data = [
        ["Events assessed", str(len(events))],
        ["Critical priorities", str(critical)],
        ["High priorities", str(high)],
        ["Behavioral anomalies", str(anomalies)],
        ["Mean priority score", f"{events['priority_score'].mean():.1f}"],
    ]
    control_data = [["Control Domain", "Alert Count"]] + [list(item) for item in top_controls.items()]
    compliance_data = [["Control", "Alerts"]] + [[name, str(count)] for name, count in sorted(mappings.items())]

    content = [
        Paragraph("Security Drift Intelligence — Executive Audit Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(
            "This report summarizes drift events, compliance exposure, and remediation priorities for security controls.",
            normal,
        ),
        Spacer(1, 12),
        Paragraph("Summary", heading),
        Table(summary_data, colWidths=[3 * inch, 4 * inch], hAlign="LEFT"),
        Spacer(1, 12),
        Paragraph("Highest-Risk Control Domains", heading),
        Table(control_data, colWidths=[3 * inch, 4 * inch], hAlign="LEFT"),
        Spacer(1, 12),
        Paragraph("Compliance Exposure", heading),
        Table(compliance_data, colWidths=[3 * inch, 4 * inch], hAlign="LEFT"),
        Spacer(1, 12),
        Paragraph("Management Assessment", heading),
        Paragraph(
            "Critical and high-priority drift should be reviewed against change approvals and restored to baseline unless an accepted, time-bound risk exception exists. Behavioral anomalies are investigative leads, not independent evidence of compromise.",
            normal,
        ),
    ]

    table_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#d3e4f1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
    )
    for table in content:
        if isinstance(table, Table):
            table.setStyle(table_style)

    doc.build(content)
    return path


def generate_remediation_playbook(events: pd.DataFrame, output_dir: str | Path) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    path = output / "remediation_playbook.md"
    lines = ["# Remediation Playbook", "", "This playbook maps observed drift to recommended fixes and response commands.", ""]
    count = 0
    for index, event in events.iterrows():
        rules = event.get("matched_rules") or []
        if not rules:
            continue
        count += 1
        lines.extend([
            f"## Event {count}: {event.get('control_name', 'Unknown Control')}",
            f"- Control Type: {event.get('control_type', 'Unknown')}",
            f"- Priority: {event.get('priority_level', 'UNKNOWN')} ({event.get('priority_score', 0)})",
            f"- Matched Rules: {', '.join(rules)}",
            f"- Compliance Impact: {', '.join(event.get('compliance_mappings', []))}",
            "",
            "### Recommended Remediation",
        ])
        for remediation in event.get("recommended_remediations", []):
            lines.append(f"- {remediation}")
        commands = event.get("recommended_remediation_commands", [])
        if commands:
            lines.extend(["", "### Implementation Command Templates", ""])
            for command in commands:
                lines.append(f"- `{command}`")
        lines.append("")
    if count == 0:
        lines.append("No actionable remediation items were identified in the current dataset.")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_compliance_report(events: pd.DataFrame, output_dir: str | Path) -> Path:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    for _, event in events.iterrows():
        for mapping in event.get("compliance_mappings", []):
            rows.append(
                {
                    "event_id": event.get("drift_event_id", event.get("event_id", "")),
                    "control_name": event.get("control_name", ""),
                    "priority_level": event.get("priority_level", ""),
                    "priority_score": event.get("priority_score", 0),
                    "compliance_control": mapping,
                    "matched_rules": json.dumps(event.get("matched_rules", [])),
                }
            )
    path = output / "compliance_violations.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path
