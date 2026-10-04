"""Dedicated, opt-in asyncio scheduler for explicitly registered handlers.

Handlers must be cooperative async functions. They should call ``checkpoint``
before external effects; the context carries the fenced lease for future tool
adapters. No models, shell commands, or response actions are installed here.
"""

# Context and runtime form one lifecycle implementation with private shared state.
# ruff: noqa: SLF001
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import inspect
import logging
import math
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from functools import partial
from types import MappingProxyType
from typing import TypeVar, final
from uuid import uuid4

from pydantic import JsonValue

from terminus.orchestration.models import AgentRun, Task
from terminus.orchestration.scheduler_models import CoordinatorLease, JobLease
from terminus.orchestration.scheduler_store import (
    SchedulerLeaseError,
    SchedulerStore,
)

_LOGGER = logging.getLogger(__name__)
_T = TypeVar("_T")
JobHandler = Callable[["JobContext"], Coroutine[object, object, JsonValue]]


class SchedulerAlreadyRunningError(RuntimeError):
    """A live coordinator already owns this database."""


class JobLeaseLostError(RuntimeError):
    """The handler no longer has permission to perform this job's work."""


@final
class JobContext:
    """Handler inputs and cooperative cancellation / ownership checkpoint."""

    def __init__(self, runtime: SchedulerRuntime, lease: JobLease) -> None:
        self.lease = lease
        self.task: Task = lease.task
        self.run: AgentRun = lease.run
        self.cancellation_event = asyncio.Event()
        self._runtime = runtime
        self._reason: str | None = None

    def _abort(self, reason: str) -> None:
        if self._reason is None:
            self._reason = reason
        self.cancellation_event.set()

    async def checkpoint(self) -> None:
        """Verify the lease immediately before a handler performs more work."""
        if self._runtime._stop_event.is_set():
            self._abort("shutdown")
        if self._reason is not None:
            self._raise_aborted()
        if await self._runtime._call(
            self._runtime.store.is_cancel_requested, self.lease
        ):
            job = await self._runtime._call(
                self._runtime.store.get_job, self.lease.org_id, self.lease.task_id
            )
            self._abort("cancelled" if job.cancellation_requested else "lost")
            self._raise_aborted()
        try:
            self.lease = await self._runtime._call(
                self._runtime.store.heartbeat,
                self.lease,
                lease_seconds=self._runtime.job_lease_seconds,
            )
        except SchedulerLeaseError as exc:
            self._abort("lost")
            raise JobLeaseLostError("Job lease was lost") from exc
        if self._reason is not None:
            self._raise_aborted()

    def _raise_aborted(self) -> None:
        if self._reason == "lost":
            raise JobLeaseLostError("Job lease was lost")
        raise asyncio.CancelledError(self._reason)


@final
class SchedulerRuntime:
    """Run bounded workers in a dedicated process with independent heartbeats.

    ``run`` acquires the database coordinator and serves until ``request_stop``
    or ``stop``. The same runtime can be started again after it has stopped.
    Empty registries are safe: they never claim queued tasks. Registry changes
    require constructing a runtime with the new mapping.
    """

    def __init__(  # noqa: C901 - validate independent deployment bounds here
        self,
        store: SchedulerStore,
        handlers: Mapping[str, JobHandler],
        *,
        worker_count: int = 4,
        global_limit: int = 4,
        per_org_limit: int = 2,
        run_timeout_seconds: float = 60,
        poll_interval: float = 0.25,
        heartbeat_interval: float = 5,
        coordinator_lease_seconds: float = 30,
        job_lease_seconds: float = 30,
        cancellation_grace_seconds: float = 1,
        owner_id: str | None = None,
    ) -> None:
        for name, value in (
            ("worker_count", worker_count),
            ("global_limit", global_limit),
            ("per_org_limit", per_org_limit),
        ):
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if worker_count > 32 or global_limit > 32 or per_org_limit > global_limit:
            raise ValueError(
                "Concurrency must be at most 32 and tenant limit <= global limit"
            )
        if (
            not math.isfinite(run_timeout_seconds)
            or not 1 <= run_timeout_seconds <= 3600
        ):
            raise ValueError("run_timeout_seconds must be between 1 and 3600")
        for name, value in (
            ("poll_interval", poll_interval),
            ("heartbeat_interval", heartbeat_interval),
            ("coordinator_lease_seconds", coordinator_lease_seconds),
            ("job_lease_seconds", job_lease_seconds),
            ("cancellation_grace_seconds", cancellation_grace_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        if heartbeat_interval * 2 >= min(coordinator_lease_seconds, job_lease_seconds):
            raise ValueError(
                "Heartbeat interval must be less than half each lease duration"
            )
        if (
            not 1 <= coordinator_lease_seconds <= 300
            or not 1 <= job_lease_seconds <= 300
        ):
            raise ValueError("Lease durations must be between 1 and 300 seconds")
        for role, handler in handlers.items():
            if type(role) is not str or not role.strip() or len(role) > 120:
                raise ValueError(
                    "Handler roles must be nonempty strings of at most 120 characters"
                )
            if not inspect.iscoroutinefunction(handler):
                raise TypeError(f"Handler for {role!r} must be an async function")
        if owner_id is not None and (not owner_id.strip() or len(owner_id) > 200):
            raise ValueError(
                "owner_id must be a nonempty string of at most 200 characters"
            )
        self.store = store
        self.handlers = MappingProxyType(dict(handlers))
        self.worker_count = worker_count
        self.global_limit = global_limit
        self.per_org_limit = per_org_limit
        self.run_timeout_seconds = run_timeout_seconds
        self.poll_interval = poll_interval
        self.heartbeat_interval = heartbeat_interval
        self.coordinator_lease_seconds = coordinator_lease_seconds
        self.job_lease_seconds = job_lease_seconds
        self.cancellation_grace_seconds = cancellation_grace_seconds
        self.owner_id = owner_id or str(uuid4())
        self._stop_event = asyncio.Event()
        self._stopped_event = asyncio.Event()
        self._stopped_event.set()
        self._running = False
        self._coordinator: CoordinatorLease | None = None
        self._executor: ThreadPoolExecutor | None = None
        self._contexts: set[JobContext] = set()
        self._ownership_lost = False
        self._workers_drained = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._running

    def request_stop(self) -> None:
        """Signal graceful shutdown, suitable for a process signal callback."""
        self._stop_event.set()
        for context in tuple(self._contexts):
            context._abort("lost" if self._ownership_lost else "shutdown")

    async def stop(self) -> None:
        """Cancel active handlers, persist safe outcomes, and release ownership."""
        self.request_stop()
        await self._stopped_event.wait()

    async def _call(
        self, function: Callable[..., _T], *args: object, **kwargs: object
    ) -> _T:
        if self._executor is None:
            raise RuntimeError("Scheduler runtime is not running")
        return await asyncio.get_running_loop().run_in_executor(
            self._executor, partial(function, *args, **kwargs)
        )

    async def _pause(self, seconds: float) -> None:
        with suppress(TimeoutError):
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)

    async def run(self) -> None:
        if self._running:
            raise RuntimeError("This scheduler runtime is already running")
        self._running = True
        self._stop_event.clear()
        self._stopped_event.clear()
        self._ownership_lost = False
        self._workers_drained.clear()
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="terminus-scheduler-db"
        )
        tasks: list[asyncio.Task[None]] = []
        try:
            self._coordinator = await self._call(
                self.store.acquire_coordinator,
                self.owner_id,
                lease_seconds=self.coordinator_lease_seconds,
            )
            if self._coordinator is None:
                raise SchedulerAlreadyRunningError(
                    "A live scheduler already owns this database"
                )
            await self._call(self.store.recover_expired, self.owner_id)
            coordinator = asyncio.create_task(
                self._coordinate(), name="scheduler-coordinator"
            )
            tasks.append(coordinator)
            tasks.extend(
                asyncio.create_task(
                    self._worker(index), name=f"scheduler-worker-{index}"
                )
                for index in range(min(self.worker_count, self.global_limit))
            )
            await asyncio.gather(*tasks[1:])
            self._workers_drained.set()
            await coordinator
        finally:
            self.request_stop()
            # Workers observe the event themselves: don't interrupt persistence.
            if tasks:
                await asyncio.gather(*tasks[1:], return_exceptions=True)
                self._workers_drained.set()
                await asyncio.gather(tasks[0], return_exceptions=True)
            try:
                if self._coordinator is not None:
                    await self._call(self.store.release_coordinator, self._coordinator)
            finally:
                self._coordinator = None
                await self._call(self.store.db.close)
                self._executor.shutdown(wait=True, cancel_futures=True)
                self._executor = None
                self._running = False
                self._stopped_event.set()

    async def _coordinate(self) -> None:
        while not self._workers_drained.is_set():
            with suppress(TimeoutError):
                await asyncio.wait_for(
                    self._workers_drained.wait(), self.heartbeat_interval
                )
            if self._workers_drained.is_set():
                break
            try:
                if self._coordinator is None:
                    raise SchedulerLeaseError("Missing coordinator lease")
                self._coordinator = await self._call(
                    self.store.renew_coordinator,
                    self._coordinator,
                    lease_seconds=self.coordinator_lease_seconds,
                )
                await self._call(self.store.recover_expired, self.owner_id)
            except SchedulerLeaseError:
                self._ownership_lost = True
                self.request_stop()
                return
            except Exception:
                self._ownership_lost = True
                self.request_stop()
                _LOGGER.exception("Coordinator heartbeat failed; scheduler is stopping")
                raise

    async def _worker(self, index: int) -> None:
        while not self._stop_event.is_set():
            try:
                lease = await self._call(
                    self.store.claim_next,
                    self.owner_id,
                    f"worker-{index}",
                    tuple(self.handlers),
                    lease_seconds=self.job_lease_seconds,
                    global_limit=self.global_limit,
                    per_org_limit=self.per_org_limit,
                )
            except SchedulerLeaseError:
                self._ownership_lost = True
                self.request_stop()
                return
            if lease is None:
                await self._pause(self.poll_interval)
                continue
            await self._execute(lease)

    async def _heartbeat(self, context: JobContext) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            try:
                if context._reason == "lost":
                    return
                if context._reason is None:
                    await context.checkpoint()
                else:
                    # Keep the lease fenced until cancellation settles or the
                    # uncooperative handler is durably held for reconciliation.
                    context.lease = await self._call(
                        self.store.heartbeat,
                        context.lease,
                        lease_seconds=self.job_lease_seconds,
                        allow_cancellation=True,
                    )
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None and current.cancelling():
                    raise
            except (JobLeaseLostError, SchedulerLeaseError):
                context._abort("lost")
                return
            except Exception:
                context._abort("lost")
                _LOGGER.exception("Job heartbeat failed; stopping handler")
                return

    async def _execute(self, lease: JobLease) -> None:
        context = JobContext(self, lease)
        self._contexts.add(context)
        try:
            await context.checkpoint()
        except asyncio.CancelledError:
            await self._persist_abort(context)
            self._contexts.discard(context)
            return
        except JobLeaseLostError:
            self._contexts.discard(context)
            return
        handler = asyncio.create_task(self.handlers[lease.task.role](context))
        heartbeat = asyncio.create_task(self._heartbeat(context))
        abort = asyncio.create_task(context.cancellation_event.wait())
        try:
            done, _ = await asyncio.wait(
                (handler, abort),
                timeout=self.run_timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if handler not in done or context._reason is not None:
                if context._reason is None:
                    context._abort("timeout")
                cooperative = await self._cancel_handler(handler)
                await self._persist_abort(context, cooperative=cooperative)
                return
            await self._finish_handler(context, handler)
        except (JobLeaseLostError, SchedulerLeaseError):
            context._abort("lost")
            cooperative = await self._cancel_handler(handler)
            if not cooperative:
                await self._persist_abort(context, cooperative=False)
        except asyncio.CancelledError:
            context._abort("shutdown")
            cooperative = await self._cancel_handler(handler)
            await self._persist_abort(context, cooperative=cooperative)
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
        except Exception as exc:
            await self._call(self.store.fail, context.lease, self._error(exc))
        finally:
            heartbeat.cancel()
            abort.cancel()
            await asyncio.gather(heartbeat, abort, return_exceptions=True)
            self._contexts.discard(context)

    async def _finish_handler(
        self, context: JobContext, handler: asyncio.Task[JsonValue]
    ) -> None:
        try:
            result = handler.result()
        except asyncio.CancelledError:
            context._abort("interrupted")
            await self._persist_abort(context)
        except Exception as exc:
            # An exception may declare ``retryable = False`` (terminal, no retry).
            await self._call(
                self.store.fail,
                context.lease,
                self._error(exc),
                retryable=getattr(exc, "retryable", True) is not False,
            )
        else:
            # Re-check cancellation/ownership after a handler returns.
            await context.checkpoint()
            await self._call(self.store.complete, context.lease, result)

    async def _cancel_handler(self, handler: asyncio.Task[JsonValue]) -> bool:
        if handler.done():
            # Always retrieve failures, including a return racing cancellation.
            with suppress(asyncio.CancelledError, Exception):
                handler.result()
            return True
        handler.cancel()
        done, _ = await asyncio.wait(
            (handler,), timeout=self.cancellation_grace_seconds
        )
        if handler not in done:
            # A handler suppressing cancellation must never get a replacement
            # in this process or publish its eventual result.
            self.request_stop()
            handler.add_done_callback(self._consume_handler)
            _LOGGER.error("Handler ignored cancellation; scheduler is stopping")
            return False
        self._consume_handler(handler)
        return True

    @staticmethod
    def _consume_handler(handler: asyncio.Task[JsonValue]) -> None:
        with suppress(asyncio.CancelledError, Exception):
            handler.result()

    async def _persist_abort(
        self, context: JobContext, *, cooperative: bool = True
    ) -> None:
        if context._reason == "lost" or self._ownership_lost:
            return
        with suppress(SchedulerLeaseError):
            if not cooperative:
                await self._call(
                    self.store.hold,
                    context.lease,
                    "Handler ignored coroutine cancellation; reconciliation required",
                )
            elif context._reason == "cancelled":
                await self._call(self.store.cancel, context.lease)
            else:
                await self._call(
                    self.store.fail,
                    context.lease,
                    f"Handler {context._reason or 'interrupted'}",
                    retryable=True,
                )

    @staticmethod
    def _error(exc: Exception) -> str:
        return f"{type(exc).__name__}: {exc}"[:16000]
