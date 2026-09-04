from __future__ import annotations

from terminus.agent.tools import InvestigationTools
from terminus.core.ids import OrgId
from terminus.llm.base import LlmClient
from terminus.llm.verdict import VerdictParser, build_prompt
from terminus.models import (
    Confidence,
    Evidence,
    InvestigationReport,
    Severity,
    SiemAlert,
    Verdict,
)
from terminus.policies.engine import PolicyEngine


class InvestigationAgent:
    def __init__(
        self,
        first: PolicyEngine | LlmClient | None = None,
        tools: InvestigationTools | None = None,
        second: LlmClient | PolicyEngine | None = None,
        *,
        llm: LlmClient | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        if tools is None:
            raise TypeError("InvestigationAgent requires tools parameter")
        self.tools = tools

        # Handle kwargs or positional combinations
        actual_llm = llm
        actual_policy = policy_engine

        if actual_llm is None:
            if isinstance(first, LlmClient):
                actual_llm = first
            elif isinstance(second, LlmClient):
                actual_llm = second

        if actual_policy is None:
            if isinstance(first, PolicyEngine):
                actual_policy = first
            elif isinstance(second, PolicyEngine):
                actual_policy = second
            else:
                actual_policy = PolicyEngine()

        if actual_llm is None:
            raise TypeError("InvestigationAgent requires an LlmClient instance")

        self.llm = actual_llm
        self.policy_engine = actual_policy

    async def investigate(self, alert: SiemAlert, org_id: OrgId) -> InvestigationReport:
        policy = self.policy_engine.evaluate(alert, org_id)

        if not policy.should_investigate:
            return InvestigationReport(
                alert_id=alert.id,
                policy=policy,
                verdict=Verdict(
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary="Alert ignored by policy.",
                    recommended_actions=[],
                ),
                evidence=Evidence(
                    alert=alert, agent_name=None, threat_intel="", context_notes=""
                ),
            )

        evidence = await self.tools.gather_evidence(alert, org_id)
        system_prompt, user_prompt = build_prompt(evidence)

        raw_verdict = await self.llm.respond_json(system_prompt, user_prompt)
        verdict = VerdictParser.parse(raw_verdict)

        return InvestigationReport(
            alert_id=alert.id, policy=policy, verdict=verdict, evidence=evidence
        )
