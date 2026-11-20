# File name: unavailable.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Unconfigured production SIEM: explicit gaps, never sample host telemetry.

"""Unconfigured production SIEM: explicit gaps, never sample host telemetry."""

from __future__ import annotations

from typing import Any

from terminus.core.ids import AgentId
from terminus.models import SiemAlert


class UnavailableSiemClient:
    """Placeholder SIEM client used when no source is configured; it never invents data."""
    async def get_alert(self, alert_id: str) -> SiemAlert:
        """Always raise, because without a configured source there is no real alert to
        return.
        """
        raise RuntimeError("SIEM source is not configured")

    async def get_agent(self, agent_id: AgentId) -> dict[str, Any]:
        """Report the agent as unavailable with unknown coverage instead of fabricating
        telemetry.
        """
        return {
            "id": str(agent_id),
            "status": "unavailable",
            "coverage": "unknown",
            "gaps": ["No endpoint telemetry source is configured"],
        }
