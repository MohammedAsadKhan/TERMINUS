"""Private, bounded Wazuh 4.x response transport.

This is not an authorization gateway or an enabled specialist tool. Callers must
persist and authorize dispatch intent before I/O. Acknowledgement is unverified;
ambiguous results must never be automatically retried.
"""

from __future__ import annotations

import asyncio
import json
from ipaddress import IPv4Address
from typing import Annotated, Any, Literal

import httpx2
from pydantic import Field, field_validator

from terminus.toolkit.models import Contract, Digest, Id
from terminus.toolkit.wazuh_readers import WazuhManagerSettings


class WazuhBlockRequest(Contract):
    org_id: Id
    intent_id: Id
    proposal_digest: Digest
    agent_id: Annotated[str, Field(pattern=r"^[0-9]{3,8}$")]
    source_ip: IPv4Address
    duration_seconds: int = Field(ge=30, le=900)

    @field_validator("agent_id")
    @classmethod
    def endpoint_only(cls, value: str) -> str:
        if int(value) == 0:
            raise ValueError("Manager is protected")
        return value


class DispatchOutcome(Contract):
    status: Literal["acknowledged", "denied", "unavailable", "unknown"]
    verified: Literal[False] = False
    detail: str


class WazuhResponseTransport:
    """One fixed command, one agent, no redirects, retries or raw output."""

    def __init__(
        self,
        settings: WazuhManagerSettings,
        *,
        allowed_agent_id: str,
        allowed_source_ip: IPv4Address,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.agent_id = allowed_agent_id
        self.source_ip = allowed_source_ip
        self.transport = transport

    async def _json(
        self,
        client: httpx2.AsyncClient,
        method: str,
        path: str,
        **kwargs: Any,  # noqa: ANN401
    ) -> dict[str, Any]:
        async with client.stream(method, path, **kwargs) as response:
            response.raise_for_status()
            if response.is_redirect:
                raise ValueError("Redirect rejected")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > 65536:
                    raise ValueError("Response too large")
                body.extend(chunk)
            result = json.loads(body)
            if not isinstance(result, dict):
                raise ValueError("Invalid response")
            return result

    async def dispatch(self, request: WazuhBlockRequest) -> DispatchOutcome:
        request = WazuhBlockRequest.model_validate(request.model_dump())
        if (
            request.org_id != self.settings.org_id
            or request.agent_id != self.agent_id
            or request.source_ip != self.source_ip
            or request.source_ip.is_loopback
            or request.source_ip.is_multicast
            or request.source_ip.is_unspecified
        ):
            return DispatchOutcome(status="denied", detail="Deployment scope denied")
        sending = False
        try:
            async with asyncio.timeout(10):
                async with httpx2.AsyncClient(
                    base_url=self.settings.manager_url,
                    verify=self.settings.verify_tls,
                    transport=self.transport,
                    timeout=10,
                    follow_redirects=False,
                ) as client:
                    auth = await self._json(
                        client,
                        "POST",
                        "/security/user/authenticate",
                        auth=(
                            self.settings.username.get_secret_value(),
                            self.settings.password.get_secret_value(),
                        ),
                    )
                    token = auth.get("data", {}).get("token")
                    if (
                        auth.get("error") != 0
                        or not isinstance(token, str)
                        or not token
                    ):
                        raise ValueError("Authentication failed")
                    sending = True
                    response = await self._json(
                        client,
                        "PUT",
                        "/active-response",
                        params={"agents_list": request.agent_id},
                        headers={"Authorization": f"Bearer {token}"},
                        json={
                            "command": "!terminus-ip-block",
                            "arguments": [],
                            "alert": {
                                "data": {
                                    "srcip": str(request.source_ip),
                                    "terminus_intent_id": request.intent_id,
                                    "terminus_proposal_digest": request.proposal_digest,
                                    "terminus_duration_seconds": request.duration_seconds,
                                }
                            },
                        },
                    )
                    data = response.get("data", {})
                    if (
                        response.get("error") == 0
                        and data.get("total_affected_items") == 1
                        and data.get("total_failed_items") == 0
                        and data.get("affected_items") == [request.agent_id]
                    ):
                        return DispatchOutcome(
                            status="acknowledged",
                            detail="Manager accepted command; endpoint effect unverified",
                        )
                    raise ValueError("Dispatch outcome inconclusive")
        except asyncio.CancelledError:
            # The durable caller must mark an interrupted dispatch unknown.
            raise
        except (httpx2.HTTPError, TimeoutError, ValueError, TypeError, AttributeError):
            return DispatchOutcome(
                status="unknown" if sending else "unavailable",
                detail="Dispatch requires reconciliation"
                if sending
                else "Authentication unavailable",
            )
