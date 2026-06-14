"""End-to-end orchestration for Security Drift Intelligence."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from .anomaly_engine import BehavioralAnomalyEngine
from .feature_engineering import normalize_compliance
from .priority_engine import ThreatPriorityEngine
from .risk_engine import MLRiskEngine
from .security_rules import SecurityRuleEngine


class DriftIntelligencePipeline:
    def __init__(self, model_dir: str | Path):
        model_dir = Path(model_dir)
        self.rules = SecurityRuleEngine()
        self.ml = MLRiskEngine(model_dir / "random_forest.pkl")
        self.anomaly = BehavioralAnomalyEngine(model_dir / "isolation_forest.pkl")
        self.priority = ThreatPriorityEngine()

    def models_ready(self) -> bool:
        return self.ml.pipeline is not None and self.anomaly.pipeline is not None

    def train(self, frame: pd.DataFrame) -> dict:
        metrics = self.ml.train(frame, self.ml.model_path)
        self.anomaly.train(frame, self.anomaly.model_path)
        return metrics

    def score(self, frame: pd.DataFrame) -> pd.DataFrame:
        if not self.models_ready():
            self.train(frame)
        result = frame.copy()
        result["compliance_impact"] = result["compliance_impact"].map(normalize_compliance)
        from .feature_engineering import enrich_features

        context_features = enrich_features(result)[
            ["is_approved_change", "is_ci_cd_change", "is_emergency_change"]
        ]
        rule_results = [self.rules.evaluate(row) for _, row in result.iterrows()]
        rule_frame = pd.DataFrame(rule_results, index=result.index)
        ml_frame = self.ml.predict(result)
        anomaly_frame = self.anomaly.predict(result)
        result = pd.concat([result, context_features, rule_frame, ml_frame, anomaly_frame], axis=1)
        priority_frame = self.priority.prioritize(result)
        return pd.concat([result, priority_frame], axis=1)
