from __future__ import annotations

import pytest

from terminus.agent.investigator import InvestigationAgent
from terminus.agent.tools import InvestigationTools
from terminus.core.ids import OrgId
from terminus.llm.client import ScriptedLlm
from terminus.models import Severity, SiemAlert, Tier
from terminus.policies.engine import PolicyEngine
from terminus.siem.static import StaticSiemClient


@pytest.mark.anyio
async def test_investigator_with_scripted_llm() -> None:
    # Given
    policy_engine = PolicyEngine()
    siem = StaticSiemClient()
    tools = InvestigationTools(siem)
    llm = ScriptedLlm()
    agent = InvestigationAgent(policy_engine, tools, llm)

    alert = SiemAlert.model_validate({"id": "1", "rule": {"id": 1, "level": 8}})
    org_id = OrgId("org-1")

    # When
    report = await agent.investigate(alert, org_id)

    # Then
    assert report.policy.tier == Tier.TRIAGE
    assert report.verdict.severity == Severity.MEDIUM
    assert report.verdict.summary == "Scripted test summary."
    assert "Isolate host" in report.verdict.recommended_actions
