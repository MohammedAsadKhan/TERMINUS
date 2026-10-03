"""Server-Sent Events (SSE) Real-Time Streaming Bus for TERMINUS 2.0.

Pushes live incident updates, investigation agent progress steps, and
containment notifications directly to connected analyst dashboards with strict tenant isolation.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from terminus.core.ids import OrgId
from terminus.privacy.redactor import SecretRedactor
from terminus.server.deps import get_current_org

logger = logging.getLogger("terminus.server.streaming")
streaming_router = APIRouter(prefix="/stream", tags=["Real-Time Streaming"])


class EventBroadcaster:
    """Pub/Sub event broadcaster for SSE clients with strict tenant isolation."""

    def __init__(self) -> None:
        # org_id -> list of queues
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}

    def subscribe(self, org_id: str | OrgId) -> asyncio.Queue[dict[str, Any]]:
        org_key = str(org_id)
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        if org_key not in self._subscribers:
            self._subscribers[org_key] = []
        self._subscribers[org_key].append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]], org_id: str | OrgId | None = None) -> None:
        if org_id is not None:
            org_key = str(org_id)
            if org_key in self._subscribers and q in self._subscribers[org_key]:
                self._subscribers[org_key].remove(q)
                if not self._subscribers[org_key]:
                    del self._subscribers[org_key]
                return

        for org_key in list(self._subscribers.keys()):
            if q in self._subscribers[org_key]:
                self._subscribers[org_key].remove(q)
                if not self._subscribers[org_key]:
                    del self._subscribers[org_key]

    async def broadcast_to_org(self, org_id: str | OrgId, event_type: str, data: dict[str, Any]) -> None:
        """Broadcasts an event specifically to subscribers of the given tenant organization."""
        org_key = str(org_id)
        redacted_data = SecretRedactor.redact_dict(data)
        payload = {"event": event_type, "data": redacted_data}
        for q in list(self._subscribers.get(org_key, [])):
            try:
                q.put_nowait(payload)
            except Exception:
                pass

    async def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcasts a global event to all subscribers across organizations."""
        redacted_data = SecretRedactor.redact_dict(data)
        payload = {"event": event_type, "data": redacted_data}
        for queues in list(self._subscribers.values()):
            for q in list(queues):
                try:
                    q.put_nowait(payload)
                except Exception:
                    pass


broadcaster = EventBroadcaster()


@streaming_router.get("/events")
async def sse_events(
    request: Request,
    org_id: Annotated[OrgId, Depends(get_current_org)],
) -> StreamingResponse:
    """Stream live SOC incidents and agent thoughts to the analyst console for the authenticated organization."""
    queue = broadcaster.subscribe(org_id)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Send initial connection ack
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'org_id': str(org_id), 'message': 'Terminus SSE Event Bus Online'})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"event: {msg['event']}\ndata: {json.dumps(msg['data'])}\n\n"
                except TimeoutError:
                    # Keep-alive heartbeat
                    yield ": ping\n\n"
        finally:
            broadcaster.unsubscribe(queue, org_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

