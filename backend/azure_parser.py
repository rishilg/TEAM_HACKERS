"""Microsoft Azure Activity and Entra audit normalization connector."""

from __future__ import annotations

import json
from pathlib import Path

from .schemas import UnifiedSecurityEvent


class AzureAuditParser:
    source = "Azure Audit"

    def parse_file(self, path: str | Path) -> list[UnifiedSecurityEvent]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        records = payload.get("value", payload if isinstance(payload, list) else [payload])
        return [self.parse(record) for record in records]

    def parse(self, record: dict) -> UnifiedSecurityEvent:
        operation = (
            record.get("operationName", {}).get("value")
            if isinstance(record.get("operationName"), dict)
            else record.get("operationName", record.get("activityDisplayName", "Azure Change"))
        )
        text = str(operation).lower()
        if "conditional access" in text or "authentication method" in text or "mfa" in text:
            control, severity, name = "Access_Control", "Critical", "MFA Disabled"
        elif "diagnostic" in text or "logging" in text:
            control, severity, name = "Logging", "Critical", "Audit Logging Disabled"
        elif "role assignment" in text:
            control, severity, name = "Access_Control", "High", "Admin Role Granted"
        elif "network security" in text or "firewall" in text:
            control, severity, name = "Firewall", "High", "Firewall Open To Internet"
        else:
            control, severity, name = "Cloud_Security", "Medium", str(operation)

        properties = record.get("properties") or record.get("additionalDetails") or {}
        change = "Disable" if any(word in text for word in ("disable", "delete", "remove")) else "Modify"
        return UnifiedSecurityEvent(
            event_type="configuration_change",
            control_type=control,
            change_type=change,
            severity=severity,
            compliance_impact="NIST",
            timestamp=record.get("eventTimestamp") or record.get("activityDateTime", ""),
            source=self.source,
            event_id=record.get("eventDataId") or record.get("id", ""),
            control_name=name,
            baseline_value="approved_configuration",
            current_value=json.dumps(properties, sort_keys=True),
            status="Drifted",
            change_reason="Azure Control Plane Activity",
            actor=str(record.get("caller") or record.get("initiatedBy", "unknown")),
            metadata={
                "resource_id": record.get("resourceId"),
                "category": record.get("category"),
                "raw_operation": operation,
            },
        )
