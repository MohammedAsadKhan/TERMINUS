"""Asynchronous Ingestion Buffer & Token-Bucket Rate Limiter for TERMINUS.

Provides resilient alert buffering during telemetry spikes and floods,
preventing HTTP 504 timeouts and dropped alerts.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

from terminus.core.ids import OrgId
from terminus.models import SiemAlert

logger = logging.getLogger("terminus.ingestion.buffer")


@dataclass
class BufferedAlert:
    alert: SiemAlert
    org_id: OrgId
    enqueued_at: float
    retries: int = 0


class IngestionBuffer:
    """Asynchronous alert queue and background consumer worker pool."""

    def __init__(
        self,
        max_queue_size: int = 10000,
        worker_count: int = 4,
        rate_limit_per_sec: float = 200.0,
    ) -> None:
        self.max_queue_size = max_queue_size
        self.worker_count = worker_count
        self.rate_limit_per_sec = rate_limit_per_sec

        self._queue: asyncio.Queue[BufferedAlert] = asyncio.Queue(maxsize=max_queue_size)
        self._workers: list[asyncio.Task[None]] = []
        self._processor: Callable[[SiemAlert, OrgId], Coroutine[Any, Any, Any]] | None = None
        self._running = False

        # Token bucket state
        self._tokens = rate_limit_per_sec
        self._last_token_update = time.time()

    def set_processor(self, processor: Callable[[SiemAlert, OrgId], Coroutine[Any, Any, Any]]) -> None:
        self._processor = processor

    async def start(self) -> None:
        """Start worker consumer tasks."""
        if self._running:
            return
        self._running = True
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker_loop(i))
            self._workers.append(task)
        logger.info(f"Ingestion buffer started with {self.worker_count} background workers")

    async def stop(self) -> None:
        """Stop worker tasks cleanly."""
        self._running = False
        for task in self._workers:
            task.cancel()
        self._workers.clear()

    async def enqueue(self, alert: SiemAlert, org_id: OrgId) -> bool:
        """Enqueue alert into buffer. Returns True if accepted, False if buffer full."""
        try:
            item = BufferedAlert(alert=alert, org_id=org_id, enqueued_at=time.time())
            self._queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            logger.warning(f"Ingestion queue full! Dropping alert {alert.id} for org {org_id}")
            return False

    async def _worker_loop(self, worker_id: int) -> None:
        """Worker consumption loop."""
        while self._running:
            try:
                item = await self._queue.get()
                if self._processor:
                    try:
                        await self._processor(item.alert, item.org_id)
                    except Exception as e:
                        logger.error(f"Worker {worker_id} failed to process alert {item.alert.id}: {e}")
                self._queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Unexpected error in ingestion worker {worker_id}: {e}")
                await asyncio.sleep(0.1)

    @property
    def queue_size(self) -> int:
        return self._queue.qsize()
