"""Jira API ticket store implementation."""

from __future__ import annotations

from typing import Any

import httpx2

from terminus.core.ids import OrgId, TicketId
from terminus.http import create_async_client
from terminus.models import InvestigationReport
from terminus.ticketing.base import TicketStore


class JiraTickets(TicketStore):
    """Ticket store integrated with Atlassian Jira REST API."""

    _url: str
    _user: str
    _token: str
    _project: str
    _client: httpx2.AsyncClient

    def __init__(
        self,
        jira_url: str = "",
        username: str = "",
        api_token: str = "",
        project_key: str = "",
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Initialize Jira tickets store."""
        self._url = jira_url.rstrip("/")
        self._user = username
        self._token = api_token
        self._project = project_key
        self._client = client or create_async_client()

    async def create_ticket(
        self, report: InvestigationReport, org_id: OrgId
    ) -> TicketId:
        """Create a Jira issue for an investigation report."""
        if not (self._url and self._user and self._token and self._project):
            raise RuntimeError("Jira credentials not fully configured")

        url = f"{self._url}/rest/api/2/issue"
        auth = (self._user, self._token)
        alert = report.evidence.alert
        payload = {
            "fields": {
                "project": {"key": self._project},
                "summary": f"[Terminus] {alert.rule_id}: {alert.description[:80]}",
                "description": (
                    f"Organization: {org_id}\n"
                    f"Alert ID: {alert.id}\n"
                    f"Level: {alert.level}\n"
                    f"Verdict Severity: {report.verdict.severity.value.upper()}\n"
                    f"Summary: {report.verdict.summary}\n\n"
                    f"Recommended Actions: {', '.join(report.verdict.recommended_actions)}"
                ),
                "issuetype": {"name": "Task"},
            }
        }

        res = await self._client.post(url, auth=auth, json=payload)
        res.raise_for_status()
        data: dict[str, Any] = res.json()
        key = str(data.get("key", ""))
        return TicketId(key)

    async def get_ticket(self, ticket_id: TicketId, org_id: OrgId) -> dict[str, str]:
        """Fetch Jira issue details by key."""
        if not (self._url and self._user and self._token):
            raise RuntimeError("Jira credentials not fully configured")

        url = f"{self._url}/rest/api/2/issue/{ticket_id}"
        auth = (self._user, self._token)
        res = await self._client.get(url, auth=auth)
        res.raise_for_status()
        data: dict[str, Any] = res.json()
        fields: dict[str, Any] = data.get("fields", {})
        status_info: dict[str, Any] = fields.get("status", {})
        return {
            "id": ticket_id,
            "org_id": org_id,
            "summary": str(fields.get("summary", "")),
            "status": str(status_info.get("name", "Unknown")),
        }
