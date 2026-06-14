"""Deterministic enterprise rules with compliance and remediation context."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable

import pandas as pd

from .feature_engineering import event_text


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    name: str
    score: int
    risk_level: str
    explanation: str
    business_impact: str
    remediation: str
    compliance: tuple[str, ...]
    predicate: Callable[[pd.Series], bool]
    remediation_commands: tuple[str, ...] = field(default_factory=tuple)


def _contains(*terms: str) -> Callable[[pd.Series], bool]:
    return lambda row: all(term in event_text(row) for term in terms)


def _domain_change(domain: str, changes: tuple[str, ...]) -> Callable[[pd.Series], bool]:
    return lambda row: str(row.get("control_type", "")).lower() == domain and str(
        row.get("change_type", "")
    ).lower() in changes


def _remediation_command_templates(rule_name: str, row: pd.Series) -> tuple[str, ...]:
    normalized = rule_name.lower()
    if "cloudtrail disabled" in normalized:
        return (
            "aws cloudtrail update-trail --name <trail-name> --is-logging TRUE",
            "aws cloudtrail start-logging --name <trail-name>",
        )
    if "mfa disabled" in normalized:
        return (
            "aws iam enable-mfa-device --user-name <user> --serial-number <mfa-serial>",
            "az ad user update --id <user> --force-change-password-next-login true",
        )
    if "encryption downgrade" in normalized:
        return (
            "aws kms enable-key-rotation --key-id <key-id>",
            "gcloud kms keys update <key-name> --protection-level=hsm",
        )
    if "audit logging disabled" in normalized:
        return (
            "aws logs put-retention-policy --log-group-name <group> --retention-in-days 365",
            "az monitor diagnostic-settings create --name <setting> --resource <resource-id>",
        )
    if "public database exposure" in normalized:
        return (
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --cidr 0.0.0.0/0",
            "az sql server firewall-rule delete --resource-group <rg> --server <server> --name AllowAll",
        )
    if "firewall open to internet" in normalized:
        return (
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --cidr 0.0.0.0/0",
            "az network nsg rule update --name <rule> --nsg-name <nsg> --priority 100",
        )
    if "dlp rule removed" in normalized:
        return (
            "restore DLP policy from policy-as-code and redeploy to sensitive data repositories",
        )
    if "admin role granted" in normalized:
        return (
            "aws iam remove-user-from-group --user-name <user> --group-name <group>",
            "gcloud projects remove-iam-policy-binding <project> --member=user:<user> --role=<role>",
        )
    if "endpoint protection disabled" in normalized:
        return (
            "re-enable endpoint protection for the device and initiate a full malware scan",
        )
    if "cloud security policy removed" in normalized:
        return (
            "restore cloud guardrail policy in policy-as-code and redeploy the policy template",
        )
    return ()


RULES = (
    SecurityRule(
        "SDI-001", "CloudTrail Disabled", 100, "CRITICAL",
        "AWS CloudTrail was disabled, creating a direct loss of control-plane audit evidence.",
        "Incident reconstruction, privileged activity monitoring, and non-repudiation are impaired.",
        "Re-enable multi-region CloudTrail, validate log delivery, and review the actor's IAM activity.",
        ("NIST AU-2", "NIST AU-12", "CIS AWS 3.1", "PCI DSS 10.2"),
        lambda r: _contains("cloudtrail")(r) and (
            "disable" in event_text(r) or "enabled=false" in event_text(r)
        ),
    ),
    SecurityRule(
        "SDI-002", "MFA Disabled", 100, "CRITICAL",
        "Multi-factor authentication protection was removed from an identity control.",
        "Stolen credentials may be sufficient for account takeover and privileged access.",
        "Restore MFA, revoke active sessions, rotate credentials, and inspect recent sign-in activity.",
        ("NIST IA-2", "CIS Controls 6.3", "PCI DSS 8.4.2"),
        lambda r: "mfa" in event_text(r) and (
            "disable" in event_text(r) or "enabled=false" in event_text(r)
        ),
    ),
    SecurityRule(
        "SDI-003", "Encryption Downgrade", 98, "CRITICAL",
        "Encryption protection was disabled or reduced below the approved baseline.",
        "Sensitive financial and customer data may be exposed at rest or in transit.",
        "Restore the approved cipher and key configuration, rotate affected keys, and assess exposure.",
        ("NIST SC-13", "CIS Controls 3.11", "GDPR Article 32", "PCI DSS 3.5"),
        lambda r: "encryption" in event_text(r) and any(
            term in event_text(r) for term in ("disable", "downgrade", "aes-128", "enabled=false")
        ),
    ),
    SecurityRule(
        "SDI-004", "Audit Logging Disabled", 97, "CRITICAL",
        "A security audit logging control was disabled.",
        "Monitoring blind spots increase attacker dwell time and weaken forensic evidence.",
        "Restore logging, verify retention and forwarding, and investigate the change window.",
        ("NIST AU-2", "NIST AU-6", "CIS Controls 8.2", "PCI DSS 10.2"),
        _domain_change("logging", ("disable", "remove")),
    ),
    SecurityRule(
        "SDI-005", "Public Database Exposure", 100, "CRITICAL",
        "A database or data service appears reachable from the public internet.",
        "Internet exposure can lead to unauthorized access, data loss, fraud, and regulatory reporting.",
        "Remove public access, restrict security groups, rotate secrets, and review access logs.",
        ("NIST AC-4", "NIST SC-7", "CIS AWS 5.4", "GDPR Article 32", "PCI DSS 1.3.1"),
        lambda r: (
            ("database" in event_text(r) or "rds" in event_text(r))
            and any(x in event_text(r) for x in ("public", "0.0.0.0/0", "internet"))
        ),
    ),
    SecurityRule(
        "SDI-101", "Firewall Open To Internet", 88, "HIGH",
        "A firewall rule was broadened to an unrestricted internet source.",
        "The exposed service has a materially larger attack surface.",
        "Restrict the source CIDR and port range, validate business need, and scan the exposed asset.",
        ("NIST AC-4", "NIST SC-7", "CIS Controls 4.4", "PCI DSS 1.3.1"),
        lambda r: str(r.get("control_type", "")).lower() == "firewall" and (
            any(x in event_text(r) for x in ("0.0.0.0/0", "internet", "public"))
        ),
    ),
    SecurityRule(
        "SDI-102", "DLP Rule Removed", 86, "HIGH",
        "A data loss prevention policy or enforcement rule was removed.",
        "Sensitive data exfiltration may no longer be detected or blocked.",
        "Restore the DLP policy, inspect recent transfers, and require approval for future exceptions.",
        ("NIST SI-4", "CIS Controls 3.13", "GDPR Article 32", "PCI DSS 12.3"),
        _domain_change("dlp", ("remove", "disable")),
    ),
    SecurityRule(
        "SDI-103", "Admin Role Granted", 90, "HIGH",
        "A privileged administrative role assignment was created or broadened.",
        "Excess privilege increases fraud, sabotage, and account takeover impact.",
        "Validate approval, make access time-bound, enforce MFA, and review actions taken.",
        ("NIST AC-2", "NIST AC-6", "CIS Controls 6.8", "PCI DSS 7.2"),
        lambda r: str(r.get("control_type", "")).lower() == "access_control" and (
            any(x in event_text(r) for x in ("admin", "privileged", "owner", "root"))
        ),
    ),
    SecurityRule(
        "SDI-104", "Endpoint Protection Disabled", 87, "HIGH",
        "Endpoint protection was disabled or removed from a managed device.",
        "Malware, ransomware, and credential theft may execute without preventive controls.",
        "Re-enable protection, isolate the endpoint if unexplained, and run an EDR investigation.",
        ("NIST SI-3", "CIS Controls 10.1", "PCI DSS 5.2"),
        _domain_change("endpoint", ("disable", "remove")),
    ),
    SecurityRule(
        "SDI-105", "Cloud Security Policy Removed", 88, "HIGH",
        "A cloud security guardrail or policy was removed.",
        "Cloud resources may be deployed outside approved security and compliance boundaries.",
        "Restore the policy, enumerate resources created during the gap, and enforce policy-as-code.",
        ("NIST CM-3", "CIS Controls 4.1", "PCI DSS 6.5.1"),
        _domain_change("cloud_security", ("remove", "disable")),
    ),
)


class SecurityRuleEngine:
    def evaluate(self, event: pd.Series | dict) -> dict:
        row = event if isinstance(event, pd.Series) else pd.Series(event)
        matches = [rule for rule in RULES if rule.predicate(row)]
        if not matches:
            return {
                "security_rule_score": 0,
                "rule_risk_level": "LOW",
                "matched_rules": [],
                "rule_explanations": [],
                "compliance_mappings": [],
                "recommended_remediations": [],
                "recommended_remediation_commands": [],
            }
        matches.sort(key=lambda rule: rule.score, reverse=True)
        top = matches[0]
        commands = [
            cmd for rule in matches for cmd in _remediation_command_templates(rule.name, row)
        ]
        return {
            "security_rule_score": top.score,
            "rule_risk_level": top.risk_level,
            "matched_rules": [rule.name for rule in matches],
            "rule_explanations": [rule.explanation for rule in matches],
            "compliance_mappings": sorted({item for rule in matches for item in rule.compliance}),
            "recommended_remediations": [rule.remediation for rule in matches],
            "recommended_remediation_commands": commands,
        }

    def catalog(self) -> list[dict]:
        catalog = []
        for rule in RULES:
            entry = {key: value for key, value in asdict(rule).items() if key != "predicate"}
            entry["remediation_commands"] = _remediation_command_templates(rule.name, pd.Series({}))
            catalog.append(entry)
        return catalog
