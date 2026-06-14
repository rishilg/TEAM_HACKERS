"""SOC-style GenAI copilot with deterministic offline operation."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


class SecurityCopilot:
    def __init__(self, provider: str | None = None, api_key: str | None = None):
        self.provider = (provider or os.getenv("LLM_PROVIDER", "openai")).lower()
        self.api_key = api_key or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY")

    @staticmethod
    def _fallback(event: dict) -> dict:
        rules = event.get("matched_rules") or ["Configuration Drift"]
        mappings = event.get("compliance_mappings") or [
            str(event.get("compliance_impact", "NIST"))
        ]
        remediation = event.get("recommended_remediations") or [
            "Validate authorization, restore the approved baseline, and review related activity."
        ]
        commands = event.get("recommended_remediation_commands") or []
        rule = rules[0]
        control = str(event.get("control_name") or event.get("control_type", "security control"))
        summary = f"{rule} detected on {control} with {event.get('priority_level', 'unknown')} priority."
        emergency = event.get("is_emergency_change")
        ci_cd = event.get("is_ci_cd_change")
        reason = str(event.get("change_reason", "unknown")).strip()
        context_closure = []
        if emergency:
            context_closure.append(
                "The change appears to be emergency or break-glass related; confirm a documented time-bound exception."
            )
        if ci_cd:
            context_closure.append(
                "The event may be tied to CI/CD deployment activity; verify it is an authorized automated release rather than an unchecked vulnerability."
            )
        return {
            "security_summary": summary,
            "business_impact": (
                "The drift weakens a preventive or detective control and may increase fraud, "
                "data exposure, service disruption, or investigation cost."
                " If the change exposes internal services or a network boundary, it may also violate "
                "NIST SC-7 boundary protection requirements."
            ),
            "compliance_impact": "Potential control gaps: " + ", ".join(mappings) + ".",
            "root_cause_analysis": (
                f"The change was recorded as '{reason}' by "
                f"{event.get('operator_name') or event.get('actor') or 'an unidentified actor'}. "
                "Confirm whether the change was approved and whether compensating controls existed. "
                + " ".join(context_closure)
            ),
            "recommended_remediation": " ".join(remediation),
            "recommended_remediation_commands": commands,
            "audit_narrative": (
                f"Security monitoring identified {rule}. Priority score "
                f"{event.get('priority_score', 0)}/100. The event should remain open until the "
                "approved baseline is restored or a documented risk exception is accepted. "
                + ("Document CI/CD deployment context if applicable. " if ci_cd else "")
                + ("Emergency changes require post-facto review and revocation once resolved. " if emergency else "")
            ),
            "generation_mode": "deterministic",
        }

    def analyze(self, event: dict) -> dict:
        if not self.api_key:
            return self._fallback(event)
        try:
            if self.provider == "gemini":
                return self._call_gemini(event)
            return self._call_openai(event)
        except (urllib.error.URLError, TimeoutError, ValueError, KeyError, json.JSONDecodeError):
            result = self._fallback(event)
            result["generation_mode"] = "deterministic_fallback"
            return result

    @staticmethod
    def _prompt(event: dict) -> str:
        safe_event = {
            key: event.get(key)
            for key in [
                "control_name",
                "control_type",
                "change_type",
                "severity",
                "status",
                "change_reason",
                "priority_score",
                "priority_level",
                "matched_rules",
                "compliance_mappings",
                "rule_explanations",
            ]
        }
        return (
            "You are a financial-services SOC analyst. Return only valid JSON with keys "
            "security_summary, business_impact, compliance_impact, root_cause_analysis, "
            "recommended_remediation, audit_narrative. Be concise, evidence-based, and do not "
            f"invent facts. Event: {json.dumps(safe_event, default=str)}"
        )

    def _call_openai(self, event: dict) -> dict:
        request = urllib.request.Request(
            "https://api.openai.com/v1/responses",
            data=json.dumps(
                {
                    "model": os.getenv("OPENAI_MODEL", "gpt-4.1-mini"),
                    "input": self._prompt(event),
                    "text": {"format": {"type": "json_object"}},
                }
            ).encode(),
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            payload = json.load(response)
        result = json.loads(payload["output"][0]["content"][0]["text"])
        result["generation_mode"] = "openai"
        return result

    def _call_gemini(self, event: dict) -> dict:
        model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            f"?key={self.api_key}"
        )
        request = urllib.request.Request(
            url,
            data=json.dumps(
                {
                    "contents": [{"parts": [{"text": self._prompt(event)}]}],
                    "generationConfig": {"responseMimeType": "application/json"},
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=25) as response:
            payload = json.load(response)
        result = json.loads(payload["candidates"][0]["content"]["parts"][0]["text"])
        result["generation_mode"] = "gemini"
        return result
