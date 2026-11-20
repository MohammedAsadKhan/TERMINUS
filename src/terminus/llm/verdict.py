# File name: verdict.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Build investigation prompts and parse structured model verdicts.

from __future__ import annotations

from terminus.llm.base import JsonValue
from terminus.models import Evidence, Verdict


def build_prompt(evidence: Evidence) -> tuple[str, str]:
    """Build the system and user prompts for an alert from the evidence's level, description, agent,
    threat intelligence and context.
    """
    system = "You are a senior security analyst. Analyze the provided alert evidence and output your verdict as a JSON object."
    user = f"""Alert Level: {evidence.alert.level}
Alert Description: {evidence.alert.description}
Agent: {evidence.agent_name}
Threat Intel: {evidence.threat_intel}
Context: {evidence.context_notes}

Expected JSON keys: "severity" (low|medium|high|critical), "confidence" (low|medium|high), "summary" (string), "recommended_actions" (list of strings)."""
    return system, user


class VerdictParser:
    """Namespace for converting raw model output into a Verdict."""

    @staticmethod
    def parse(raw: dict[str, JsonValue]) -> Verdict:
        """Validate the raw model output against the Verdict schema, raising if it does not conform.
        """
        return Verdict.model_validate(raw)
