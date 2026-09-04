"""Unit tests for Slack, Twilio, Jira, and Wazuh live adapters."""

from __future__ import annotations

import pytest

from terminus.core.ids import AgentId, OrgId, TicketId
from terminus.models import (
    Confidence,
    Evidence,
    InvestigationReport,
    PolicyResult,
    Severity,
    SiemAlert,
    Tier,
    Verdict,
)
from terminus.notifiers.slack import SlackNotifier
from terminus.notifiers.twilio import TwilioSmsNotifier
from terminus.siem.wazuh import WazuhClient
from terminus.ticketing.jira import JiraTickets


@pytest.fixture
def sample_report() -> InvestigationReport:
    """Fixture providing a sample investigation report."""
    alert = SiemAlert.model_validate(
        {"id": "alert-99", "rule": {"id": 100, "level": 10}}
    )
    policy = PolicyResult(
        alert_id="alert-99",
        tier=Tier.ESCALATE,
        should_investigate=True,
        reason="High level",
    )
    verdict = Verdict(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        summary="Test threat detected",
        recommended_actions=["Isolate host"],
    )
    evidence = Evidence(
        alert=alert,
        agent_name="web-01",
        threat_intel="Malicious IP",
        context_notes="SSH brute force",
    )
    return InvestigationReport(
        alert_id="alert-99", policy=policy, verdict=verdict, evidence=evidence
    )


@pytest.mark.anyio
async def test_slack_notifier_inactive_when_no_url(
    sample_report: InvestigationReport,
) -> None:
    """Slack notifier returns False if webhook_url is empty."""
    notifier = SlackNotifier(webhook_url="")
    res = await notifier.notify(sample_report, OrgId("org_test"))
    assert res is False


@pytest.mark.anyio
async def test_twilio_notifier_inactive_when_missing_creds(
    sample_report: InvestigationReport,
) -> None:
    """Twilio notifier returns False if creds are missing."""
    notifier = TwilioSmsNotifier(
        account_sid="", auth_token="", from_number="", to_number=""
    )
    res = await notifier.notify(sample_report, OrgId("org_test"))
    assert res is False


@pytest.mark.anyio
async def test_jira_tickets_unconfigured_raises_error(
    sample_report: InvestigationReport,
) -> None:
    """Jira store raises RuntimeError when unconfigured."""
    jira = JiraTickets()
    with pytest.raises(RuntimeError, match="Jira credentials not fully configured"):
        await jira.create_ticket(sample_report, OrgId("org_test"))

    with pytest.raises(RuntimeError, match="Jira credentials not fully configured"):
        await jira.get_ticket(TicketId("PROJ-1"), OrgId("org_test"))


@pytest.mark.anyio
async def test_wazuh_client_unconfigured_raises_error() -> None:
    """Wazuh client raises RuntimeError on alert fetch when base_url is empty."""
    client = WazuhClient(base_url="")
    with pytest.raises(RuntimeError, match="Wazuh URL not configured"):
        await client.get_alert("123")

    agent = await client.get_agent(AgentId("001"))
    assert agent["status"] == "disconnected"
