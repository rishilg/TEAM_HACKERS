"""Feature creation and transparent security-label derivation."""

from __future__ import annotations

import re

import numpy as np
import pandas as pd

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_SCORE = {"info": 5, "low": 20, "medium": 50, "high": 75, "critical": 100}
STATUS_SCORE = {
    "compliant": 5,
    "remediated": 15,
    "mitigated": 30,
    "under_review": 60,
    "drifted": 90,
}
CHANGE_SCORE = {
    "enable": 10,
    "update": 25,
    "rollback": 45,
    "modify": 60,
    "remove": 85,
    "disable": 90,
}
COMPLIANCE_ALIASES = {
    "NI": "NIST",
    "CI": "CIS",
    "GD": "GDPR",
    "PC": "PCI",
    "IS": "ISO",
    "PCI-DSS": "PCI",
    "GDPR 32": "GDPR",
}
APPROVED_CHANGE_TERMS = {
    "security update",
    "approved change",
    "approved deployment",
    "automation",
    "ci/cd",
    "cicd",
    "pipeline",
    "gitops",
    "infra as code",
    "infrastructure as code",
    "automated deployment",
    "scheduled deployment",
}
CI_CD_TERMS = {
    "ci/cd",
    "cicd",
    "pipeline",
    "automated deployment",
    "deployment job",
    "gitops",
    "build pipeline",
    "release pipeline",
    "deployment pipeline",
}
EMERGENCY_CHANGE_TERMS = {
    "emergency",
    "hotfix",
    "break glass",
    "urgent",
    "incident response",
    "emergency maintenance",
    "outage",
    "critical patch",
    "incident remediation",
}


def normalize_compliance(value: object) -> str:
    text = str(value or "").strip().upper()
    if text in {"", "NAN", "NONE"}:
        return "NONE"
    return COMPLIANCE_ALIASES.get(text, text.split()[0])


def enrich_features(frame: pd.DataFrame) -> pd.DataFrame:
    df = frame.copy()
    for column, default in {
        "severity": "Info",
        "status": "Under_Review",
        "change_type": "Modify",
        "control_type": "Unknown",
        "change_reason": "Unknown",
        "compliance_impact": "NONE",
        "change_date": pd.Timestamp.utcnow().isoformat(),
        "control_name": "",
        "baseline_value": "",
        "current_value": "",
    }.items():
        if column not in df:
            df[column] = default

    timestamps = pd.to_datetime(df["change_date"], errors="coerce", utc=True)
    timestamps = timestamps.fillna(pd.Timestamp.now(tz="UTC"))
    df["hour"] = timestamps.dt.hour
    df["day_of_week"] = timestamps.dt.dayofweek
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
    df["is_after_hours"] = ((df["hour"] < 7) | (df["hour"] > 19)).astype(int)
    df["month"] = timestamps.dt.month
    df["severity_score"] = df["severity"].astype(str).str.lower().map(SEVERITY_SCORE).fillna(10)
    df["status_score"] = df["status"].astype(str).str.lower().map(STATUS_SCORE).fillna(50)
    df["change_score"] = df["change_type"].astype(str).str.lower().map(CHANGE_SCORE).fillna(50)
    df["compliance_impact"] = df["compliance_impact"].map(normalize_compliance)
    df["has_compliance_impact"] = (df["compliance_impact"] != "NONE").astype(int)
    df["value_changed"] = (
        df["baseline_value"].astype(str).str.lower() != df["current_value"].astype(str).str.lower()
    ).astype(int)
    event_texts = df.apply(event_text, axis=1)
    approved_pattern = r"\b(?:" + "|".join(map(re.escape, APPROVED_CHANGE_TERMS)) + r")\b"
    ci_cd_pattern = r"\b(?:" + "|".join(map(re.escape, CI_CD_TERMS)) + r")\b"
    emergency_pattern = r"\b(?:" + "|".join(map(re.escape, EMERGENCY_CHANGE_TERMS)) + r")\b"
    df["is_approved_change"] = event_texts.str.contains(approved_pattern, regex=True, case=False).astype(int)
    df["is_ci_cd_change"] = event_texts.str.contains(ci_cd_pattern, regex=True, case=False).astype(int)
    df["is_emergency_change"] = event_texts.str.contains(emergency_pattern, regex=True, case=False).astype(int)
    return df


def derive_security_labels(frame: pd.DataFrame) -> pd.Series:
    """Create auditable weak labels from risk factors, not random target values."""
    df = enrich_features(frame)
    score = (
        0.38 * df["severity_score"]
        + 0.25 * df["status_score"]
        + 0.20 * df["change_score"]
        + 8 * df["has_compliance_impact"]
        + 5 * df["is_after_hours"]
        + 4 * df["is_weekend"]
    )

    risky_controls = df["control_type"].astype(str).str.lower().isin(
        ["logging", "encryption", "access_control", "firewall", "data_protection", "cloud_security"]
    )
    destructive_change = df["change_type"].astype(str).str.lower().isin(["disable", "remove"])
    score += (risky_controls & destructive_change).astype(int) * 12

    approved = (
        df["is_approved_change"] == 1
        ) & df["status"].astype(str).str.lower().isin(["compliant", "remediated"])
    score -= approved.astype(int) * 25

    score -= df["is_ci_cd_change"].astype(int) * 18
    score += df["is_emergency_change"].astype(int) * 10
    score = np.clip(score, 0, 100)
    return pd.cut(
        score,
        bins=[-1, 34, 59, 79, 100],
        labels=RISK_ORDER,
        include_lowest=True,
    ).astype(str)


def event_text(row: pd.Series | dict) -> str:
    getter = row.get
    fields = [
        getter("scenario_name", ""),
        getter("control_name", ""),
        getter("control_type", ""),
        getter("change_type", ""),
        getter("change_reason", ""),
        getter("baseline_value", ""),
        getter("current_value", ""),
    ]
    return re.sub(r"[_\-]+", " ", " ".join(map(str, fields))).lower()
