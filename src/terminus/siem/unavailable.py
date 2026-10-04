"""Unconfigured production SIEM: explicit gaps, never sample host telemetry."""

from __future__ import annotations

from typing import Any

from terminus.core.ids import AgentId
from terminus.models import SiemAlert


class UnavailableSiemClient:
    async def get_alert(self, alert_id: str) -> SiemAlert:
        raise RuntimeError("SIEM source is not configured")

    async def get_agent(self, agent_id: AgentId) -> dict[str, Any]:
        return {
            "id": str(agent_id),
            "status": "unavailable",
            "coverage": "unknown",
            "gaps": ["No endpoint telemetry source is configured"],
        }
