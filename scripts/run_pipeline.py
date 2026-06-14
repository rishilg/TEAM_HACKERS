"""Run scoring, cloud connector demos, validation, and audit reporting."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.azure_parser import AzureAuditParser
from backend.cloudtrail_parser import CloudTrailParser
from backend.pipeline import DriftIntelligencePipeline
from backend.reporting import (
    export_compliance_report,
    generate_executive_report,
    generate_executive_report_pdf,
    generate_remediation_playbook,
)
from backend.validation_engine import ValidationEngine


def normalized_events() -> pd.DataFrame:
    aws = CloudTrailParser().parse_file(ROOT / "data" / "aws_cloudtrail_mock.json")
    azure = AzureAuditParser().parse_file(ROOT / "data" / "azure_audit_mock.json")
    rows = [event.to_dict() for event in aws + azure]
    cloud = pd.DataFrame(rows).rename(columns={"timestamp": "change_date"})
    cloud.to_json(
        ROOT / "reports" / "normalized_cloud_events.json",
        orient="records",
        indent=2,
        date_format="iso",
    )
    return cloud


def main() -> None:
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    events = pd.read_csv(ROOT / "data" / "config_drift_events.csv")
    pipeline = DriftIntelligencePipeline(ROOT / "models")
    if not pipeline.models_ready() or not (reports / "model_metrics.json").exists():
        metrics = pipeline.train(events)
        (reports / "model_metrics.json").write_text(
            json.dumps(metrics, indent=2), encoding="utf-8"
        )
        pd.DataFrame(metrics["feature_importance"]).to_csv(
            reports / "feature_importance.csv", index=False
        )

    scored = pipeline.score(events)
    cloud_scored = pipeline.score(normalized_events())
    combined = pd.concat([scored, cloud_scored], ignore_index=True)
    combined.to_json(
        reports / "scored_events.json",
        orient="records",
        indent=2,
        date_format="iso",
    )
    combined.drop(
        columns=[
            "matched_rules",
            "rule_explanations",
            "compliance_mappings",
            "recommended_remediations",
        ]
    ).to_csv(reports / "scored_events.csv", index=False)

    validation = ValidationEngine(pipeline)
    scenarios = pd.read_csv(ROOT / "data" / "validation_scenarios.csv")
    validation_results, validation_metrics = validation.validate(scenarios)
    validation.save(validation_results, validation_metrics, reports)
    generate_executive_report(combined, reports / "audit_reports")
    generate_executive_report_pdf(combined, reports / "audit_reports")
    generate_remediation_playbook(combined, reports / "audit_reports")
    export_compliance_report(combined, reports / "audit_reports")
    print(
        json.dumps(
            {
                "events_scored": len(combined),
                "critical": int((combined["priority_level"] == "CRITICAL").sum()),
                "validation_accuracy": validation_metrics["accuracy"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
