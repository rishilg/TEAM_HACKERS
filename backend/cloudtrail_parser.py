"""AWS CloudTrail normalization connector."""

from __future__ import annotations

import json
from pathlib import Path

from .schemas import UnifiedSecurityEvent


EVENT_MAP = {
    "StopLogging": ("Logging", "Disable", "Critical", "CloudTrail Disabled"),
    "DeleteTrail": ("Logging", "Remove", "Critical", "CloudTrail Removed"),
    "AuthorizeSecurityGroupIngress": ("Firewall", "Modify", "High", "Firewall Rule Changed"),
    "PutBucketEncryption": ("Encryption", "Modify", "High", "Encryption Configuration Changed"),
    "CreatePolicyVersion": ("Access_Control", "Modify", "High", "IAM Policy Changed"),
}


class CloudTrailParser:
    source = "AWS CloudTrail"

    def parse_file(self, path: str | Path) -> list[UnifiedSecurityEvent]:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        records = payload.get("Records", payload if isinstance(payload, list) else [payload])
        return [self.parse(record) for record in records]

    def parse(self, record: dict) -> UnifiedSecurityEvent:
        event_name = record.get("eventName", "UnknownAwsEvent")
        control, change, severity, control_name = EVENT_MAP.get(
            event_name, ("Cloud_Security", "Modify", "Medium", event_name)
        )
        request = record.get("requestParameters") or {}
        response = record.get("responseElements") or {}
        user = record.get("userIdentity") or {}
        return UnifiedSecurityEvent(
            event_type="configuration_change",
            control_type=control,
            change_type=change,
            severity=severity,
            compliance_impact="NIST",
            timestamp=record.get("eventTime", ""),
            source=self.source,
            event_id=record.get("eventID", ""),
            control_name=control_name,
            baseline_value="approved_configuration",
            current_value=json.dumps({"request": request, "response": response}, sort_keys=True),
            status="Drifted",
            change_reason="Cloud API Activity",
            actor=user.get("arn") or user.get("principalId", "unknown"),
            metadata={
                "aws_region": record.get("awsRegion"),
                "source_ip": record.get("sourceIPAddress"),
                "raw_event_name": event_name,
            },
        )
