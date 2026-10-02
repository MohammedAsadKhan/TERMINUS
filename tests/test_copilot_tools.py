"""Incident copilot tools must stay read-only and tenant scoped."""

from __future__ import annotations

import pytest

from terminus.server.copilot_tools import IncidentTools


class TicketStoreStub:
    def __init__(self) -> None:
        self.tickets = {
            "org-a": [
                {"id": "TICK-A", "rule_description": "SSH failures", "agent_name": "auth-01", "severity": "high", "status": "OPEN", "source_ip": "203.0.113.77", "full_log": "37 failed SSH logins from 203.0.113.77 to 10.0.0.5", "mitigation_status": "NOT_EXECUTED"},
                {"id": "TICK-B", "rule_description": "Web lookup", "agent_name": "web-01", "severity": "high", "status": "OPEN", "source_ip": "203.0.113.77", "full_log": "203.0.113.77 GET /lookup to 10.0.0.9", "mitigation_status": "NOT_EXECUTED"},
            ],
            "org-b": [
                {"id": "TICK-PRIVATE", "rule_description": "Other tenant", "agent_name": "private-host", "source_ip": "198.51.100.9", "full_log": "private event"},
            ],
        }

    async def list_tickets(self, org_id):
        return self.tickets.get(str(org_id), [])

    async def get_ticket(self, ticket_id, org_id):
        for ticket in self.tickets.get(str(org_id), []):
            if ticket["id"] == ticket_id:
                return ticket
        raise LookupError(ticket_id)


@pytest.mark.asyncio
async def test_tools_correlate_structured_sources_without_leaking_tenants() -> None:
    tools = IncidentTools(TicketStoreStub(), "org-a")
    correlated = await tools.execute("correlate_sources", {})
    assert correlated["observed_sources"][0]["ip"] == "203.0.113.77"
    assert correlated["observed_sources"][0]["incident_count"] == 2
    assert "10.0.0.5" not in [item["ip"] for item in correlated["observed_sources"]]
    assert "198.51.100.9" not in [item["ip"] for item in correlated["observed_sources"]]

    listed = await tools.execute("list_incidents", {})
    assert {item["id"] for item in listed["incidents"]} == {"TICK-A", "TICK-B"}
    assert listed["incidents"][0]["mitigation_status"] == "NOT_EXECUTED"
    assert (await tools.execute("get_incident", {"ticket_id": "TICK-PRIVATE"}))["error"]


@pytest.mark.asyncio
async def test_search_exposes_matching_raw_evidence() -> None:
    tools = IncidentTools(TicketStoreStub(), "org-a")
    result = await tools.execute("search_incidents", {"query": "auth-01"})
    assert result["total"] == 1
    assert "37 failed SSH logins" in result["incidents"][0]["raw_event_excerpt"]
