"""Canonical event contracts used by every ingestion connector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class UnifiedSecurityEvent:
    event_type: str
    control_type: str
    change_type: str
    severity: str
    compliance_impact: str
    timestamp: str
    source: str
    event_id: str = ""
    control_name: str = ""
    baseline_value: str = ""
    current_value: str = ""
    status: str = "Under_Review"
    change_reason: str = "Unknown"
    actor: str = ""
    approver: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
