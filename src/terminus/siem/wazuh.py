"""Wazuh SIEM API client implementation using httpx2."""

from __future__ import annotations

from typing import Any

import httpx2

from terminus.core.ids import AgentId
from terminus.http import create_async_client
from terminus.models import SiemAlert
from terminus.siem.base import SiemClient


class WazuhClient(SiemClient):
    """Client for interacting with the Wazuh SIEM REST API."""

    _base_url: str
    _username: str
    _password: str
    _client: httpx2.AsyncClient
    _token: str | None

    def __init__(
        self,
        base_url: str,
        username: str = "",
        password: str = "",
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Initialize the Wazuh API client."""
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._client = client or create_async_client()
        self._token = None

    async def _authenticate(self) -> str:
        """Authenticate with Wazuh API and obtain JWT token."""
        if self._token:
            return self._token

        url = f"{self._base_url}/security/user/authenticate"
        auth = (self._username, self._password)
        response = await self._client.post(url, auth=auth)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        data_inner: dict[str, Any] = data.get("data", {})
        token = str(data_inner.get("token", ""))
        self._token = token
        return token

    async def get_alert(self, alert_id: str) -> SiemAlert:
        """Fetch alert details from Wazuh API."""
        if not self._base_url:
            raise RuntimeError("Wazuh URL not configured")
        token = await self._authenticate()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self._base_url}/alerts/{alert_id}"
        response = await self._client.get(url, headers=headers)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        payload = data.get("data", {})
        return SiemAlert.model_validate(payload)

    async def get_agent(self, agent_id: AgentId) -> dict[str, Any]:
        """Fetch agent details from Wazuh API."""
        if not self._base_url:
            return {"id": agent_id, "name": "unknown", "status": "disconnected"}
        try:
            token = await self._authenticate()
            headers = {"Authorization": f"Bearer {token}"}
            url = f"{self._base_url}/agents?agents_list={agent_id}"
            response = await self._client.get(url, headers=headers)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            data_inner: dict[str, Any] = data.get("data", {})
            items: list[Any] = data_inner.get("affected_items", [])
            if items and isinstance(items[0], dict):
                res: dict[str, Any] = items[0]
                return res
            return {"id": agent_id, "status": "not_found"}
        except Exception:
            return {"id": agent_id, "status": "unknown"}
