"""Train both analytical models and persist evaluation artifacts."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.pipeline import DriftIntelligencePipeline


def main() -> None:
    data_path = ROOT / "data" / "config_drift_events.csv"
    models = ROOT / "models"
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    frame = pd.read_csv(data_path)
    pipeline = DriftIntelligencePipeline(models)
    metrics = pipeline.train(frame)
    (reports / "model_metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    pd.DataFrame(metrics["feature_importance"]).to_csv(
        reports / "feature_importance.csv", index=False
    )
    print(
        f"Trained on {len(frame)} events. "
        f"CV macro-F1={metrics['cross_validation_f1_macro_mean']:.3f}"
    )


if __name__ == "__main__":
    main()
