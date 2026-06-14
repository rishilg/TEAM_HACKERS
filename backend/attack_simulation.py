"""Attack scenario simulation for security drift events."""

from __future__ import annotations

import pandas as pd

ATTACK_PATTERNS = {
    "CloudTrail Disabled": (
        "Evidence Tampering",
        "An attacker attempts to remove or disable logging to cover malicious activity and hinder incident response.",
    ),
    "MFA Disabled": (
        "Account Takeover",
        "A loss of multi-factor authentication opens a path for credential-based access and privilege escalation.",
    ),
    "Encryption Downgrade": (
        "Data Exposure",
        "Reduced cryptographic controls may allow sensitive data to be accessed or intercepted in transit or at rest.",
    ),
    "Audit Logging Disabled": (
        "Visibility Evasion",
        "An adversary is likely trying to avoid detection by disabling or degrading audit and monitoring controls.",
    ),
    "Public Database Exposure": (
        "Data Exfiltration",
        "An exposed database is a likely target for unauthorized access, data theft, or ransomware-related encryption.",
    ),
    "Firewall Open To Internet": (
        "Lateral Movement",
        "A broadly opened network control can enable attackers to reach internal services and move laterally.",
    ),
    "DLP Rule Removed": (
        "Exfiltration Bypass",
        "Data loss prevention controls appear weakened, increasing the chance that sensitive data will leave the network unnoticed.",
    ),
    "Admin Role Granted": (
        "Privilege Escalation",
        "An attacker may have gained or strengthened privileged access to critical systems or data.",
    ),
    "Endpoint Protection Disabled": (
        "Malware Persistence",
        "Endpoint defenses have been disabled, raising the risk of ransomware, backdoors, or persistent malicious implants.",
    ),
    "Cloud Security Policy Removed": (
        "Cloud Configuration Attack",
        "Cloud guardrails were removed, enabling insecure resource deployment and policy drift risks.",
    ),
}

DEFAULT_PATTERN = (
    "Suspicious Drift",
    "The observed configuration drift matches an elevated risk event; validate authorization and containment controls.",
)


class AttackSimulator:
    def generate_scenarios(self, events: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
        selected = (
            events.dropna(subset=["priority_score"]) \
            .sort_values(["priority_score", "anomaly_confidence"], ascending=[False, False])
            .head(top_n)
        )
        scenarios = []
        for _, event in selected.iterrows():
            pattern_name, description = self._derive_attack_pattern(event)
            scenarios.append(
                {
                    "control_name": event.get("control_name", "Unknown Control"),
                    "control_type": event.get("control_type", "Unknown"),
                    "priority_level": event.get("priority_level", "UNKNOWN"),
                    "priority_score": event.get("priority_score", 0),
                    "anomaly_confidence": event.get("anomaly_confidence", 0),
                    "matched_rules": event.get("matched_rules", []),
                    "attack_pattern": pattern_name,
                    "scenario_description": description,
                    "recommended_remediation": event.get("recommended_remediations", []),
                    "recommended_remediation_commands": event.get("recommended_remediation_commands", []),
                }
            )
        return pd.DataFrame(scenarios)

    def _derive_attack_pattern(self, event: pd.Series) -> tuple[str, str]:
        matched_rules = event.get("matched_rules") or []
        for rule in matched_rules:
            if rule in ATTACK_PATTERNS:
                return ATTACK_PATTERNS[rule]
        if str(event.get("control_type", "")).lower() == "firewall":
            return ATTACK_PATTERNS["Firewall Open To Internet"]
        if str(event.get("control_type", "")).lower() in {"database", "rds"}:
            return ATTACK_PATTERNS["Public Database Exposure"]
        return DEFAULT_PATTERN
