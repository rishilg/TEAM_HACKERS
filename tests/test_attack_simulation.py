from __future__ import annotations

import pandas as pd

from backend.attack_simulation import AttackSimulator


def test_attack_simulator_generates_scenarios() -> None:
    frame = pd.DataFrame(
        [
            {
                "control_name": "Customer DB",
                "control_type": "Database",
                "priority_level": "CRITICAL",
                "priority_score": 98,
                "anomaly_confidence": 82.5,
                "matched_rules": ["Public Database Exposure"],
                "recommended_remediations": ["Remove public access."],
                "recommended_remediation_commands": ["aws ec2 revoke-security-group-ingress --group-id <sg-id> --cidr 0.0.0.0/0"],
            }
        ]
    )
    scenarios = AttackSimulator().generate_scenarios(frame, top_n=1)
    assert len(scenarios) == 1
    assert scenarios.loc[0, "attack_pattern"] == "Data Exfiltration"
    assert "Public Database Exposure" in scenarios.loc[0, "matched_rules"]
    assert "recommended_remediation_commands" in scenarios.columns
