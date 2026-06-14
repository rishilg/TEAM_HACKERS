"""Behavioral unusualness detection, deliberately independent of severity."""

from __future__ import annotations

import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .feature_engineering import enrich_features

ANOMALY_CATEGORICAL = ["control_type", "change_type", "compliance_impact", "change_reason"]
ANOMALY_NUMERIC = ["hour", "day_of_week", "is_weekend", "is_after_hours", "month"]
MODEL_JOBS = int(os.getenv("SDI_MODEL_JOBS", "1"))
MODEL_SCHEMA_VERSION = 1


class BehavioralAnomalyEngine:
    def __init__(self, model_path: str | Path | None = None):
        self.model_path = Path(model_path) if model_path else None
        self.pipeline: Pipeline | None = None
        if self.model_path and self._artifact_is_compatible(self.model_path):
            self.pipeline = joblib.load(self.model_path)

    @staticmethod
    def _artifact_is_compatible(path: Path) -> bool:
        metadata_path = path.with_suffix(".meta.json")
        if not path.exists() or not metadata_path.exists():
            return False
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return (
            metadata.get("schema_version") == MODEL_SCHEMA_VERSION
            and metadata.get("sklearn_version") == sklearn.__version__
        )

    def train(self, frame: pd.DataFrame, output_path: str | Path | None = None) -> None:
        df = enrich_features(frame)
        preprocess = ColumnTransformer(
            [
                (
                    "categorical",
                    OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                    ANOMALY_CATEGORICAL,
                ),
                ("numeric", StandardScaler(), ANOMALY_NUMERIC),
            ]
        )
        model = IsolationForest(
            n_estimators=160,
            contamination=0.08,
            max_samples="auto",
            random_state=42,
            n_jobs=MODEL_JOBS,
        )
        self.pipeline = Pipeline([("preprocess", preprocess), ("model", model)])
        self.pipeline.fit(df[ANOMALY_CATEGORICAL + ANOMALY_NUMERIC])
        path = Path(output_path) if output_path else self.model_path
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.pipeline, path, compress=3)
            path.with_suffix(".meta.json").write_text(
                json.dumps(
                    {
                        "schema_version": MODEL_SCHEMA_VERSION,
                        "sklearn_version": sklearn.__version__,
                        "model_type": "IsolationForest",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            self.model_path = path

    def predict(self, frame: pd.DataFrame) -> pd.DataFrame:
        if self.pipeline is None:
            raise RuntimeError("Anomaly model is not trained or loaded.")
        df = enrich_features(frame)
        x = df[ANOMALY_CATEGORICAL + ANOMALY_NUMERIC]
        decision = self.pipeline.decision_function(x)
        flags = self.pipeline.predict(x) == -1
        low, high = np.percentile(decision, [5, 95])
        confidence = np.clip((high - decision) / max(high - low, 1e-9) * 100, 0, 100)
        result = pd.DataFrame(index=frame.index)
        result["anomaly_score"] = np.round(decision, 4)
        result["anomaly_flag"] = flags
        result["anomaly_confidence"] = np.round(confidence, 2)
        return result
