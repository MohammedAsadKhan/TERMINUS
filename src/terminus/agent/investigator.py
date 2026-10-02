"""Investigation Agent module for TERMINUS 2.0."""

from __future__ import annotations

from terminus.agent.react_agent import ReActAgent
from terminus.agent.tools import InvestigationTools
from terminus.core.ids import OrgId
from terminus.llm.base import LlmClient
from terminus.models import (
    Confidence,
    Evidence,
    InvestigationReport,
    Severity,
    SiemAlert,
    Verdict,
)
from terminus.policies.engine import PolicyEngine
from terminus.tools.threat_intel import ThreatIntelClient


class InvestigationAgent:
    """Orchestrator combining policy triage and the ReAct forensic investigator."""

    def __init__(
        self,
        first: PolicyEngine | LlmClient | None = None,
        tools: InvestigationTools | None = None,
        second: LlmClient | PolicyEngine | None = None,
        *,
        llm: LlmClient | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
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
        self.react_agent = ReActAgent(llm=self.llm, threat_intel=ThreatIntelClient())
        self.tools = tools

    async def investigate(
        self, alert: SiemAlert, org_id: OrgId
    ) -> InvestigationReport:
        policy = self.policy_engine.evaluate(alert, org_id)

        if not policy.should_investigate:
            return InvestigationReport(
                alert_id=alert.id,
                policy=policy,
                verdict=Verdict(
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    summary="Alert filtered into IGNORE tier by deterministic policy engine.",
                    recommended_actions=[],
                ),
                evidence=Evidence(
                    alert=alert,
                    agent_name=alert.agent_name,
                    threat_intel="Clean",
                    context_notes="Deterministic policy suppression rule matched.",
                ),
            )

        verdict, citations, evidence = await self.react_agent.run_investigation(
            alert=alert,
            org_id=org_id,
            policy=policy,
        )

        return InvestigationReport(
            alert_id=alert.id,
            policy=policy,
            verdict=verdict,
            evidence=evidence,
        )
