"""Scenario-based control validation and regression metrics."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from .feature_engineering import RISK_ORDER


class ValidationEngine:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def validate(self, scenarios: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
        frame = scenarios.copy()
        if "change_date" not in frame:
            frame["change_date"] = pd.to_datetime("2026-06-01") + pd.to_timedelta(
                frame.get("hour", 12), unit="h"
            )
        frame["control_name"] = frame.get("scenario_name", "")
        frame["baseline_value"] = frame.get("baseline_value", "approved")
        frame["current_value"] = frame.get("current_value", "changed")
        scored = self.pipeline.score(frame)
        expected = scored["expected_risk"].str.upper()
        predicted = scored["priority_level"].str.upper()
        scored["validation_pass"] = expected == predicted
        metrics = {
            "accuracy": float(accuracy_score(expected, predicted)),
            "classification_report": classification_report(
                expected, predicted, labels=RISK_ORDER, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(expected, predicted, labels=RISK_ORDER).tolist(),
            "labels": RISK_ORDER,
            "total_scenarios": len(scored),
            "passed_scenarios": int(scored["validation_pass"].sum()),
        }
        return scored, metrics

    @staticmethod
    def save(scored: pd.DataFrame, metrics: dict, output_dir: str | Path) -> None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        scored.to_csv(output / "validation_results.csv", index=False)
        (output / "validation_metrics.json").write_text(
            json.dumps(metrics, indent=2), encoding="utf-8"
        )
