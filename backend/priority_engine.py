"""Threat-centric prioritization with deterministic risk floors."""

from __future__ import annotations

import numpy as np
import pandas as pd


def priority_level(score: float) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


class ThreatPriorityEngine:
    CRITICAL_FLOORS = {
        "CloudTrail Disabled": 95,
        "MFA Disabled": 95,
        "Encryption Downgrade": 93,
        "Audit Logging Disabled": 92,
        "Public Database Exposure": 96,
    }

    def prioritize(self, frame: pd.DataFrame) -> pd.DataFrame:
        df = frame.copy()
        base = (
            0.50 * df["security_rule_score"].astype(float)
            + 0.35 * df["ml_risk_score"].astype(float)
            + 0.15 * df["anomaly_confidence"].astype(float)
        )
        scores = []
        reasons = []
        for index, row in df.iterrows():
            score = float(base.loc[index])
            floor_reason = ""
            matches = row.get("matched_rules", [])
            if isinstance(matches, str):
                matches = [matches]
            for name, floor in self.CRITICAL_FLOORS.items():
                if name in matches and score < floor:
                    score = floor
                    floor_reason = f"Mandatory priority floor applied for {name}"
            if str(row.get("severity", "")).lower() == "critical" and str(
                row.get("status", "")
            ).lower() == "drifted":
                score = max(score, 78)
                floor_reason = floor_reason or "Critical unresolved drift floor applied"
            if str(row.get("severity", "")).lower() == "medium" and str(
                row.get("status", "")
            ).lower() == "under_review":
                score = max(score, 42)
                floor_reason = floor_reason or "Unresolved medium-severity review floor applied"

            has_critical_rule = any(name in self.CRITICAL_FLOORS for name in matches)
            is_critical_drift = (
                str(row.get("severity", "")).lower() == "critical"
                and str(row.get("status", "")).lower() == "drifted"
            )
            if not has_critical_rule and not is_critical_drift:
                score = min(score, 84.99)
            scores.append(round(float(np.clip(score, 0, 100)), 2))
            reasons.append(floor_reason or "Weighted rule, ML risk, and behavioral anomaly signals")
        result = pd.DataFrame(index=df.index)
        result["priority_score"] = scores
        result["priority_level"] = [priority_level(value) for value in scores]
        result["priority_reason"] = reasons
        return result
