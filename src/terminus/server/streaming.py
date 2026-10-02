"""Server-Sent Events (SSE) Real-Time Streaming Bus for TERMINUS 2.0.

Pushes live incident updates, investigation agent progress steps, and
containment notifications directly to connected analyst dashboards.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

logger = logging.getLogger("terminus.server.streaming")
streaming_router = APIRouter(prefix="/stream", tags=["Real-Time Streaming"])


class EventBroadcaster:
    """Pub/Sub event broadcaster for SSE clients."""

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[dict[str, Any]]] = []

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)

    async def broadcast(self, event_type: str, data: dict[str, Any]) -> None:
        payload = {"event": event_type, "data": data}
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except Exception:
                pass


broadcaster = EventBroadcaster()


@streaming_router.get("/events")
async def sse_events(request: Request) -> StreamingResponse:
    """Stream live SOC incidents and agent thoughts to the analyst console."""
    queue = broadcaster.subscribe()

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            # Send initial connection ack
            yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'message': 'Terminus SSE Event Bus Online'})}\n\n"
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
            broadcaster.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
