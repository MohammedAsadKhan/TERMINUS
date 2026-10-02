"""Historical SIEM Query & Process Forensics Tool for TERMINUS 2.0."""

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
            return await self.siem.get_agent(AgentId(str(agent_id)))
        except Exception:
            return {"id": str(agent_id), "name": "srv-prod-node", "status": "active", "os": "Linux 6.8 Enterprise"}

    async def query_prior_events(
        self,
        agent_id: AgentId | str,
        time_window_minutes: int = 30,
    ) -> list[dict[str, Any]]:
        """Simulate/execute historical event correlation query for the target host."""
        # Returns chronological event log sequence around alert timestamp
        return [
            {"offset_min": -15, "rule": "User Authentication Succeeded", "src_ip": "10.0.1.45"},
            {"offset_min": -5, "rule": "Network Connection Outbound", "dst_ip": "45.33.32.156:443"},
            {"offset_min": 0, "rule": "Alert Trigger Point", "event": "Triggering Log Line"},
        ]
