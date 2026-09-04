"""Static SIEM client implementation for simulation and offline tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from terminus.core.base import NotFoundError
from terminus.core.ids import AgentId
from terminus.models import SiemAlert
from terminus.siem.base import SiemClient


class StaticSiemClient(SiemClient):
    """SIEM client returning static fixtures from memory or sample JSON."""

    def __init__(self, alerts: dict[str, SiemAlert] | None = None) -> None:
        """Initialize static SIEM client."""
        self._alerts = alerts or {}

    def _load_sample_data(self) -> dict[str, Any]:
        """Load fallback sample alert file from disk."""
        path = Path(__file__).parent.parent.parent.parent / "data" / "sample_alert.json"
        if not path.exists():
            return {}
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    async def get_alert(self, alert_id: str) -> SiemAlert:
        """Retrieve alert by ID from internal dict or sample file."""
        if alert_id in self._alerts:
            return self._alerts[alert_id]

        data = self._load_sample_data()
        if data.get("id") == alert_id or not self._alerts:
            return SiemAlert.model_validate(data)

        raise NotFoundError(f"Alert {alert_id} not found")

    async def get_agent(self, agent_id: AgentId) -> dict[str, Any]:
        """Retrieve agent metadata fixture."""
        return {
            "id": agent_id,
            "name": "sample-ubuntu-agent",
            "ip": "192.168.1.100",
            "os": "Ubuntu 22.04 LTS",
            "status": "active",
        }
