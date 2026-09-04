from __future__ import annotations

from typing import Any, Protocol

from terminus.core.ids import AgentId
from terminus.models import SiemAlert


class SiemClient(Protocol):
    async def get_alert(self, alert_id: str) -> SiemAlert: ...

    async def get_agent(self, agent_id: AgentId) -> dict[str, Any]: ...
