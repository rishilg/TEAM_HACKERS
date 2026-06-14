"""Supervised Random Forest risk engine with probability-based scores."""

from __future__ import annotations

import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from .feature_engineering import RISK_ORDER, derive_security_labels, enrich_features

CATEGORICAL_FEATURES = [
    "control_type",
    "change_type",
    "compliance_impact",
    "change_reason",
]
NUMERIC_FEATURES = [
    "severity_score",
    "status_score",
    "change_score",
    "hour",
    "day_of_week",
    "is_weekend",
    "is_after_hours",
    "month",
    "has_compliance_impact",
    "value_changed",
    "is_approved_change",
    "is_ci_cd_change",
    "is_emergency_change",
]
RISK_POINTS = {"LOW": 15, "MEDIUM": 45, "HIGH": 75, "CRITICAL": 98}
MODEL_JOBS = int(os.getenv("SDI_MODEL_JOBS", "1"))
MODEL_SCHEMA_VERSION = 1


class MLRiskEngine:
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

    @staticmethod
    def _build_pipeline() -> Pipeline:
        preprocess = ColumnTransformer(
            [
                ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
                ("numeric", "passthrough", NUMERIC_FEATURES),
            ]
        )
        classifier = RandomForestClassifier(
            n_estimators=140,
            max_depth=11,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            random_state=42,
            n_jobs=MODEL_JOBS,
        )
        return Pipeline([("preprocess", preprocess), ("classifier", classifier)])

    def train(self, frame: pd.DataFrame, output_path: str | Path | None = None) -> dict:
        df = enrich_features(frame)
        labels = derive_security_labels(df)
        x = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
        x_train, x_test, y_train, y_test = train_test_split(
            x, labels, test_size=0.22, random_state=42, stratify=labels
        )
        self.pipeline = self._build_pipeline()
        folds = min(5, int(labels.value_counts().min()))
        cv = StratifiedKFold(n_splits=max(2, folds), shuffle=True, random_state=42)
        cv_scores = cross_val_score(self.pipeline, x_train, y_train, cv=cv, scoring="f1_macro")
        self.pipeline.fit(x_train, y_train)
        predictions = self.pipeline.predict(x_test)

        preprocessor = self.pipeline.named_steps["preprocess"]
        names = list(preprocessor.get_feature_names_out())
        importances = self.pipeline.named_steps["classifier"].feature_importances_
        feature_importance = sorted(
            [{"feature": n, "importance": float(v)} for n, v in zip(names, importances)],
            key=lambda item: item["importance"],
            reverse=True,
        )[:20]

        path = Path(output_path) if output_path else self.model_path
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.pipeline, path, compress=3)
            path.with_suffix(".meta.json").write_text(
                json.dumps(
                    {
                        "schema_version": MODEL_SCHEMA_VERSION,
                        "sklearn_version": sklearn.__version__,
                        "model_type": "RandomForestClassifier",
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            self.model_path = path

        return {
            "cross_validation_f1_macro_mean": float(cv_scores.mean()),
            "cross_validation_f1_macro_std": float(cv_scores.std()),
            "classification_report": classification_report(
                y_test, predictions, labels=RISK_ORDER, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(y_test, predictions, labels=RISK_ORDER).tolist(),
            "labels": RISK_ORDER,
            "feature_importance": feature_importance,
            "training_rows": len(x_train),
            "test_rows": len(x_test),
        }

    def predict(self, frame: pd.DataFrame) -> pd.DataFrame:
        if self.pipeline is None:
            raise RuntimeError("Risk model is not trained or loaded.")
        df = enrich_features(frame)
        x = df[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
        probabilities = self.pipeline.predict_proba(x)
        classes = self.pipeline.classes_
        scores = np.array(
            [sum(prob * RISK_POINTS[label] for prob, label in zip(row, classes)) for row in probabilities]
        )
        result = pd.DataFrame(index=frame.index)
        result["ml_risk_score"] = np.round(scores, 2)
        result["predicted_risk_level"] = self.pipeline.predict(x)
        result["ml_confidence"] = np.round(probabilities.max(axis=1) * 100, 2)
        return result
