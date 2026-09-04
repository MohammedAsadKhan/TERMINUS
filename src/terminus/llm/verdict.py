from __future__ import annotations

from terminus.llm.base import JsonValue
from terminus.models import Evidence, Verdict


def build_prompt(evidence: Evidence) -> tuple[str, str]:
    system = "You are a senior security analyst. Analyze the provided alert evidence and output your verdict as a JSON object."
    user = f"""Alert Level: {evidence.alert.level}
Alert Description: {evidence.alert.description}
Agent: {evidence.agent_name}
Threat Intel: {evidence.threat_intel}
Context: {evidence.context_notes}

Expected JSON keys: "severity" (low|medium|high|critical), "confidence" (low|medium|high), "summary" (string), "recommended_actions" (list of strings)."""
    return system, user


class VerdictParser:
    @staticmethod
    def parse(raw: dict[str, JsonValue]) -> Verdict:
        return Verdict.model_validate(raw)
