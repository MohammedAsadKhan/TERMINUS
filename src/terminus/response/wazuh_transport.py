# File name: wazuh_transport.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Private, bounded Wazuh 4.x response transport.

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
    # Validated request to block one IPv4 source for 30 to 900 seconds on one Wazuh
    # agent, bound to an intent id and approved proposal digest.
    org_id: Id
    intent_id: Id
    proposal_digest: Digest
    agent_id: Annotated[str, Field(pattern=r"^[0-9]{3,8}$")]
    source_ip: IPv4Address
    duration_seconds: int = Field(ge=30, le=900)

    @field_validator("agent_id")
    @classmethod
    def endpoint_only(cls, value: str) -> str:
        """Reject agent id 0, which is the Wazuh manager itself, so the manager can
        never be targeted.
        """
        if int(value) == 0:
            raise ValueError("Manager is protected")
        return value


class DispatchOutcome(Contract):
    # Result of one dispatch attempt; verified is always False because the manager's
    # acknowledgement does not prove the endpoint effect.
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
        """Pin the transport to one organization's manager settings, one agent and one
        source IP; nothing else can be dispatched through it.
        """
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
        """Perform one HTTP call and return its JSON object, failing on error status,
        redirects, bodies over 64 KiB or non-object JSON.
        """
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
        """Send the single fixed block command after re-validating the request against
        the pinned scope. Returns denied when out of scope, acknowledged on a clean one-
        agent success, unavailable if failure came before sending, and unknown if it
        came after, which needs reconciliation and must not be retried.
        """
        # Re-validate even though callers pass a model, then compare against the pinned
        # scope before any network I/O; scope violations never reach the manager.
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
        # Ambiguity tracking: a failure before the command is sent means nothing happened
        # ("unavailable"); a failure after it may have taken effect ("unknown").
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
                    # From here on the manager may act on the command even if we never see
                    # its reply, so errors must be reported as unknown, not as failures.
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
