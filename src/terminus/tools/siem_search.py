"""Historical SIEM Query & Process Forensics Tool for TERMINUS."""

from __future__ import annotations

from typing import Any

from terminus.core.ids import AgentId
from terminus.siem.base import SiemClient


class SiemForensicsTool:
    """Queries SIEM context, agent historical events, and process telemetry."""

    def __init__(self, siem_client: SiemClient) -> None:
        self.siem = siem_client

    async def get_host_context(self, agent_id: AgentId | str) -> dict[str, Any]:
        """Fetch endpoint host telemetry and registration status."""
        try:
            host = await self.siem.get_agent(AgentId(str(agent_id)))
        except Exception as exc:
            return {
                "id": str(agent_id),
                "query_status": "unavailable",
                "gaps": [f"Endpoint context query failed: {type(exc).__name__}"],
            }
        return {**host, "query_status": "available", "gaps": []}

    async def query_prior_events(
        self,
        agent_id: AgentId | str,
        time_window_minutes: int = 30,
    ) -> dict[str, Any]:
        """Return an explicit gap until historical event querying is configured."""
        del agent_id, time_window_minutes
        return {
            "status": "unavailable",
            "events": [],
            "gaps": ["Historical event querying is not configured for this SIEM client."],
        }
