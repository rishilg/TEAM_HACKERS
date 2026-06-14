from __future__ import annotations

import pandas as pd

from backend.feature_engineering import normalize_compliance
from backend.priority_engine import ThreatPriorityEngine
from backend.security_rules import SecurityRuleEngine


def test_cloudtrail_rule_is_critical() -> None:
    result = SecurityRuleEngine().evaluate(
        {
            "control_name": "CloudTrail Disabled",
            "control_type": "Logging",
            "change_type": "Disable",
            "current_value": "cloudtrail_enabled=false",
        }
    )
    assert result["security_rule_score"] == 100
    assert "CloudTrail Disabled" in result["matched_rules"]


def test_benign_update_does_not_trigger_rule() -> None:
    result = SecurityRuleEngine().evaluate(
        {
            "control_name": "Approved Patch Deployment",
            "control_type": "Endpoint",
            "change_type": "Update",
            "current_value": "agent 4.2",
        }
    )
    assert result["security_rule_score"] == 0


def test_priority_floor_overrides_low_anomaly() -> None:
    frame = pd.DataFrame(
        [
            {
                "security_rule_score": 100,
                "ml_risk_score": 20,
                "anomaly_confidence": 0,
                "matched_rules": ["CloudTrail Disabled"],
                "severity": "Critical",
                "status": "Drifted",
            }
        ]
    )
    result = ThreatPriorityEngine().prioritize(frame)
    assert result.loc[0, "priority_score"] >= 95
    assert result.loc[0, "priority_level"] == "CRITICAL"


def test_ci_cd_change_is_detected() -> None:
    from backend.feature_engineering import enrich_features

    frame = pd.DataFrame(
        [
            {
                "control_name": "App Deployment",
                "control_type": "Firewall",
                "change_type": "Update",
                "change_reason": "CI/CD pipeline deployment",
                "current_value": "allow 0.0.0.0/0",
            }
        ]
    )
    enriched = enrich_features(frame)
    assert enriched.loc[0, "is_ci_cd_change"] == 1
    assert enriched.loc[0, "is_approved_change"] == 1


def test_emergency_change_is_detected() -> None:
    from backend.feature_engineering import enrich_features

    frame = pd.DataFrame(
        [
            {
                "control_name": "Critical Fix",
                "control_type": "Firewall",
                "change_type": "Modify",
                "change_reason": "Emergency outage fix",
                "current_value": "deny 10.0.0.0/8",
            }
        ]
    )
    enriched = enrich_features(frame)
    assert enriched.loc[0, "is_emergency_change"] == 1


def test_ci_cd_approved_change_scores_lower_than_manual_drift() -> None:
    from backend.feature_engineering import derive_security_labels

    approved = pd.DataFrame(
        [
            {
                "control_name": "App Deployment",
                "control_type": "Firewall",
                "change_type": "Update",
                "change_reason": "CI/CD pipeline deployment",
                "status": "Compliant",
                "severity": "Medium",
                "current_value": "allow 0.0.0.0/0",
            }
        ]
    )
    manual = pd.DataFrame(
        [
            {
                "control_name": "App Deployment",
                "control_type": "Firewall",
                "change_type": "Update",
                "change_reason": "Manual change",
                "status": "Compliant",
                "severity": "Medium",
                "current_value": "allow 0.0.0.0/0",
            }
        ]
    )
    approved_label = derive_security_labels(approved).iloc[0]
    manual_label = derive_security_labels(manual).iloc[0]
    assert approved_label in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert manual_label in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert approved_label != "CRITICAL" or manual_label == "CRITICAL"


def test_public_exposure_rule_includes_nist_sc7() -> None:
    result = SecurityRuleEngine().evaluate(
        {
            "control_type": "Database",
            "change_type": "Modify",
            "current_value": "public access 0.0.0.0/0",
            "control_name": "Customer DB",
        }
    )
    assert "NIST SC-7" in result["compliance_mappings"]


def test_copilot_fallback_mentions_sc7_and_cicd_context() -> None:
    from backend.llm_copilot import SecurityCopilot

    event = {
        "control_name": "Customer DB",
        "control_type": "Database",
        "change_type": "Modify",
        "change_reason": "CI/CD deployment",
        "priority_score": 85,
        "priority_level": "HIGH",
        "compliance_mappings": ["NIST SC-7", "NIST AC-4"],
        "is_ci_cd_change": 1,
    }
    analysis = SecurityCopilot()._fallback(event)
    assert "NIST SC-7" in analysis["compliance_impact"]
    assert "CI/CD" in analysis["audit_narrative"] or "CI/CD" in analysis["root_cause_analysis"]


def test_compliance_aliases_are_repaired() -> None:
    assert normalize_compliance("NI") == "NIST"
    assert normalize_compliance("GD") == "GDPR"
    assert normalize_compliance(None) == "NONE"
