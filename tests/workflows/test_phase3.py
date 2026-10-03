import pytest
from pydantic import ValidationError

from terminus.agent.react_agent import (
    INVARIANT_BASE_SYSTEM_PROMPT,
    build_system_prompt,
)
from terminus.agent.investigator import InvestigationAgent
from terminus.core.ids import OrgId
from terminus.llm.client import ScriptedLlm
from terminus.models import SiemAlert
from terminus.server.routers import CreateAgentRequest, UpdateAgentRequest


def test_t_agt_1_system_prompt_interpolation():
    """T-AGT-1: System prompt retains invariant base and includes persona and role instructions."""
    persona = "You are a specialized Ransomware Hunting Sentinel."
    role_instr = "Inspect all vssadmin and bcdedit process command lines."

    prompt = build_system_prompt(persona_prompt=persona, role_instructions=role_instr)
    assert INVARIANT_BASE_SYSTEM_PROMPT in prompt
    assert persona in prompt
    assert role_instr in prompt

    # When persona and role are empty, invariant base is cleanly returned
    clean_prompt = build_system_prompt()
    assert clean_prompt == INVARIANT_BASE_SYSTEM_PROMPT


def test_t_agt_2_length_limits_enforcement():
    """T-AGT-2: Agent master_prompt (<=4000) and role_description (<=500) limit enforcement."""
    # Valid agent request
    req_valid = CreateAgentRequest(
        name="Valid Agent",
        role_description="A" * 500,
        master_prompt="B" * 4000,
    )
    assert req_valid.name == "Valid Agent"

    # Too long master prompt (> 4000 chars)
    with pytest.raises(ValidationError):
        CreateAgentRequest(
            name="Bad Agent",
            role_description="Valid role",
            master_prompt="B" * 4001,
        )

    # Too long role description (> 500 chars)
    with pytest.raises(ValidationError):
        CreateAgentRequest(
            name="Bad Agent",
            role_description="A" * 501,
            master_prompt="Valid prompt",
        )

    # Update request limits
    with pytest.raises(ValidationError):
        UpdateAgentRequest(master_prompt="X" * 4001)

    with pytest.raises(ValidationError):
        UpdateAgentRequest(role_description="Y" * 501)


@pytest.mark.anyio
async def test_t_agt_3_persona_investigation_execution():
    """T-AGT-3: Persona execution through ReAct agent produces structured InvestigationReport."""
    llm = ScriptedLlm()
    agent = InvestigationAgent(llm=llm)

    alert = SiemAlert(
        id="alert-persona-01",
        rule_id=100201,
        level=12,
        description="Ransomware volume shadow copy deletion attempt",
        location="/var/log/syslog",
        mitre="T1490",
        agent_name="db-prod-01",
    )

    report = await agent.investigate(
        alert=alert,
        org_id=OrgId("org-test"),
        persona_prompt="You are the Ransomware Sentinel.",
        role_instructions="Focus on destructive disk modifications.",
    )

    assert report.alert_id == "alert-persona-01"
    assert report.verdict is not None
    assert report.verdict.severity.value in ("low", "medium", "high", "critical")
    assert report.verdict.summary != ""
    assert isinstance(report.verdict.recommended_actions, list)
    assert report.evidence is not None
    assert report.evidence.agent_name == "db-prod-01"
