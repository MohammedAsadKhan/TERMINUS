"""Exercise actual async handlers against temporary durable SQLite databases."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import JsonValue

from terminus.orchestration.models import Task
from terminus.orchestration.scheduler import (
    JobContext,
    JobHandler,
    SchedulerAlreadyRunningError,
    SchedulerRuntime,
)
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database


@pytest.fixture
def store(tmp_path: Path) -> Iterator[SchedulerStore]:
    db = Database(str(tmp_path / "runtime.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("org-a", "org-b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
        db.execute(
            """INSERT INTO incidents(
                ticket_id,org_id,alert_id,severity,confidence,summary,
                recommended_actions,policy_tier,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                f"incident-{org}",
                org,
                f"alert-{org}",
                "high",
                "high",
                "Test",
                "[]",
                "standard",
                now,
            ),
        )
    yield SchedulerStore(db)
    db.close()


def _admit(
    store: SchedulerStore,
    *,
    org: str = "org-a",
    role: str = "analyst",
    attempts: int = 3,
    priority: int = 100,
) -> Task:
    task = store.records.create_incident_task(
        org,
        f"incident-{org}",
        "triage",
        role,
        "Inspect test incident",
        priority=priority,
    )
    store.enqueue_task(org, task.task_id, max_attempts=attempts)
    return task


def _runtime(
    store: SchedulerStore,
    handlers: Mapping[str, JobHandler],
    *,
    worker_count: int = 4,
    global_limit: int = 4,
    per_org_limit: int = 2,
    run_timeout_seconds: float = 3,
    cancellation_grace_seconds: float = 0.05,
    coordinator_lease_seconds: float = 1,
) -> SchedulerRuntime:
    return SchedulerRuntime(
        store,
        handlers,
        poll_interval=0.01,
        heartbeat_interval=0.05,
        job_lease_seconds=1,
        coordinator_lease_seconds=coordinator_lease_seconds,
        run_timeout_seconds=run_timeout_seconds,
        cancellation_grace_seconds=cancellation_grace_seconds,
        worker_count=worker_count,
        global_limit=global_limit,
        per_org_limit=per_org_limit,
    )


async def _until(condition: Callable[[], bool], *, deadline: float = 4) -> None:
    async with asyncio.timeout(deadline):
        while not condition():  # noqa: ASYNC110 - observe durable DB state
            await asyncio.sleep(0.01)


async def _status(store: SchedulerStore, task: Task, status: str) -> None:
    await _until(lambda: store.get_job(task.org_id, task.task_id).status == status)


async def _stop(runtime: SchedulerRuntime, runner: asyncio.Task[None]) -> None:
    await asyncio.wait_for(runtime.stop(), 4)
    await asyncio.wait_for(runner, 4)


@pytest.mark.asyncio
async def test_registered_callback_publishes_real_result(store: SchedulerStore) -> None:
    task = _admit(store)
    visited: list[str] = []

    async def handler(context: JobContext) -> JsonValue:
        await context.checkpoint()
        visited.append(context.task.task_id)
        assert context.run.status == "running"
        return {"investigated": context.task.incident_id, "events": 7}

    runtime = _runtime(store, {"analyst": handler}, coordinator_lease_seconds=30)
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "completed")
    finally:
        await _stop(runtime, runner)
    assert visited == [task.task_id]
    job = store.get_job(task.org_id, task.task_id)
    assert job.attempt == 1
    assert store.records.get_task(task.org_id, task.task_id).status == "completed"
    runs = store.records.list_agent_runs(task.org_id, task_id=task.task_id)
    assert len(runs) == 1
    assert runs[0].status == "completed"
    assert runs[0].result == {"investigated": task.incident_id, "events": 7}


@pytest.mark.asyncio
async def test_empty_registry_and_unsupported_role_never_claim(
    store: SchedulerStore,
) -> None:
    task = _admit(store, role="unsupported")
    calls = 0

    async def handler(_context: JobContext) -> JsonValue:
        nonlocal calls
        calls += 1
        return {"ok": True}

    for registry in ({}, {"analyst": handler}):
        runtime = _runtime(store, registry)
        runner = asyncio.create_task(runtime.run())
        try:
            await _until(
                lambda: (
                    store.db.fetchone(
                        "SELECT 1 FROM orchestration_scheduler_coordinator"
                    )
                    is not None
                )
            )
            await asyncio.sleep(0.08)
        finally:
            await _stop(runtime, runner)
    assert calls == 0
    assert store.get_job(task.org_id, task.task_id).status == "queued"
    assert store.get_job(task.org_id, task.task_id).attempt == 0
    assert store.records.list_agent_runs(task.org_id, task_id=task.task_id) == []


@pytest.mark.asyncio
async def test_failure_retries_callback_with_distinct_tracked_runs(
    store: SchedulerStore,
) -> None:
    task = _admit(store)
    offset = timedelta()
    store.clock = lambda: datetime.now(UTC) + offset
    runs: list[str] = []

    async def handler(context: JobContext) -> JsonValue:
        runs.append(context.run.run_id)
        if len(runs) == 1:
            raise ValueError("transient callback failure")
        return {"attempt": context.lease.attempt}

    runtime = _runtime(store, {"analyst": handler}, coordinator_lease_seconds=30)
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "retry_wait")
        assert "transient callback failure" in (
            store.get_job(task.org_id, task.task_id).error or ""
        )
        offset = timedelta(seconds=6)
        await _status(store, task, "completed")
    finally:
        await _stop(runtime, runner)
    assert len(set(runs)) == 2
    assert store.get_job(task.org_id, task.task_id).attempt == 2
    assert sorted(
        run.status
        for run in store.records.list_agent_runs(
            task.org_id,
            task_id=task.task_id,
        )
    ) == ["completed", "failed"]


@pytest.mark.asyncio
async def test_retry_budget_exhaustion_is_terminal(store: SchedulerStore) -> None:
    task = _admit(store, attempts=1)
    calls = 0

    async def handler(_context: JobContext) -> JsonValue:
        nonlocal calls
        calls += 1
        raise RuntimeError("callback failed")

    runtime = _runtime(store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "failed")
        await asyncio.sleep(0.08)
    finally:
        await _stop(runtime, runner)
    assert calls == 1
    assert store.records.get_task(task.org_id, task.task_id).status == "failed"


@pytest.mark.asyncio
async def test_running_cancel_interrupts_callback_and_persists_cancelled(
    store: SchedulerStore,
) -> None:
    task = _admit(store)
    entered = asyncio.Event()
    interrupted = asyncio.Event()

    async def handler(_context: JobContext) -> JsonValue:
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            interrupted.set()
        return None

    runtime = _runtime(store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        store.request_cancel(task.org_id, task.task_id)
        await _status(store, task, "cancelled")
    finally:
        await _stop(runtime, runner)
    assert interrupted.is_set()
    runs = store.records.list_agent_runs(task.org_id, task_id=task.task_id)
    assert runs[0].status == "cancelled"
    assert runs[0].result is None


@pytest.mark.asyncio
async def test_cancel_requested_before_return_cannot_publish_success(
    store: SchedulerStore,
) -> None:
    task = _admit(store)

    async def handler(_context: JobContext) -> JsonValue:
        store.request_cancel(task.org_id, task.task_id)
        return {"must_not_publish": True}

    runtime = _runtime(store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "cancelled")
    finally:
        await _stop(runtime, runner)
    assert (
        store.records.list_agent_runs(task.org_id, task_id=task.task_id)[0].result
        is None
    )


@pytest.mark.asyncio
async def test_timeout_interrupts_callback_and_records_failure(
    store: SchedulerStore,
) -> None:
    task = _admit(store, attempts=1)
    interrupted = asyncio.Event()

    async def handler(_context: JobContext) -> JsonValue:
        try:
            await asyncio.Event().wait()
        finally:
            interrupted.set()
        return None

    runtime = _runtime(store, {"analyst": handler}, run_timeout_seconds=1)
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "failed")
    finally:
        await _stop(runtime, runner)
    assert interrupted.is_set()
    assert store.get_job(task.org_id, task.task_id).error == "Handler timeout"


@pytest.mark.asyncio
async def test_heartbeats_renew_without_handler_checkpoints(
    store: SchedulerStore,
) -> None:
    task = _admit(store)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def handler(_context: JobContext) -> JsonValue:
        entered.set()
        await release.wait()
        return {"renewed": True}

    runtime = _runtime(store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        before = store.get_job(task.org_id, task.task_id)
        coordinator_before = store.db.fetchone(
            "SELECT * FROM orchestration_scheduler_coordinator"
        )
        await asyncio.sleep(1.15)
        after = store.get_job(task.org_id, task.task_id)
        coordinator_after = store.db.fetchone(
            "SELECT * FROM orchestration_scheduler_coordinator"
        )
        assert after.status == "running"
        assert after.attempt == 1
        assert before.heartbeat_at is not None
        assert after.heartbeat_at is not None
        assert after.lease_expires_at is not None
        assert coordinator_before is not None
        assert coordinator_after is not None
        assert after.heartbeat_at > before.heartbeat_at
        assert after.lease_expires_at > datetime.now(UTC)
        assert coordinator_after["heartbeat_at"] > coordinator_before["heartbeat_at"]
        release.set()
        await _status(store, task, "completed")
    finally:
        release.set()
        await _stop(runtime, runner)


@pytest.mark.asyncio
async def test_only_one_runtime_coordinates_database(store: SchedulerStore) -> None:
    task = _admit(store)
    entered = asyncio.Event()

    async def handler(_context: JobContext) -> JsonValue:
        entered.set()
        await asyncio.Event().wait()
        return None

    first = _runtime(store, {"analyst": handler})
    other_db = Database(store.db.db_path)
    second = _runtime(SchedulerStore(other_db), {"analyst": handler})
    runner = asyncio.create_task(first.run())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        with pytest.raises(SchedulerAlreadyRunningError):
            await second.run()
        assert store.get_job(task.org_id, task.task_id).attempt == 1
        assert not second.running
    finally:
        await _stop(first, runner)
        other_db.close()


@pytest.mark.asyncio
async def test_shutdown_is_durable_and_same_runtime_can_restart(
    store: SchedulerStore,
) -> None:
    task = _admit(store)
    entered = asyncio.Event()
    calls = 0
    offset = timedelta()
    store.clock = lambda: datetime.now(UTC) + offset

    async def handler(_context: JobContext) -> JsonValue:
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            await asyncio.Event().wait()
        return {"restarted": True}

    runtime = _runtime(store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    await asyncio.wait_for(entered.wait(), 3)
    await _stop(runtime, runner)
    assert store.get_job(task.org_id, task.task_id).status == "retry_wait"
    assert (
        store.db.fetchone("SELECT * FROM orchestration_scheduler_coordinator") is None
    )
    offset = timedelta(seconds=6)
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(store, task, "completed")
    finally:
        await _stop(runtime, runner)
    assert calls == 2
    assert store.get_job(task.org_id, task.task_id).attempt == 2


@pytest.mark.asyncio
async def test_uncooperative_handler_is_held_through_long_cancellation_grace(
    store: SchedulerStore,
) -> None:
    task = _admit(store)
    entered = asyncio.Event()
    release = asyncio.Event()
    handler_finished = asyncio.Event()
    calls = 0

    async def handler(_context: JobContext) -> JsonValue:
        nonlocal calls
        calls += 1
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await release.wait()
        finally:
            if release.is_set():
                handler_finished.set()
        return {"late_result": True}

    runtime = _runtime(store, {"analyst": handler}, cancellation_grace_seconds=1.2)
    runner = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        store.request_cancel(task.org_id, task.task_id)
        await asyncio.wait_for(runner, 4)
        assert not runtime.running
        job = store.get_job(task.org_id, task.task_id)
        assert job.status == "waiting"
        assert "reconciliation" in (job.recovery_reason or "")
        assert store.records.get_task(task.org_id, task.task_id).status == "waiting"
        replacement = _runtime(store, {"analyst": handler})
        replacement_runner = asyncio.create_task(replacement.run())
        try:
            await asyncio.sleep(0.15)
        finally:
            await _stop(replacement, replacement_runner)
        assert calls == 1
        release.set()
        await asyncio.wait_for(handler_finished.wait(), 2)
        await asyncio.sleep(0)
        assert store.get_job(task.org_id, task.task_id).status == "waiting"
        assert (
            store.records.list_agent_runs(task.org_id, task_id=task.task_id)[0].result
            is None
        )
    finally:
        release.set()
        if runtime.running:
            await _stop(runtime, runner)


@pytest.mark.asyncio
async def test_workers_enforce_global_and_tenant_concurrency(
    store: SchedulerStore,
) -> None:
    tasks = [_admit(store) for _ in range(3)] + [
        _admit(store, org="org-b") for _ in range(2)
    ]
    release = asyncio.Event()
    active: dict[str, int] = {}
    peak = 0
    tenant_peaks: dict[str, int] = {}

    async def handler(context: JobContext) -> JsonValue:
        nonlocal peak
        org = context.task.org_id
        active[org] = active.get(org, 0) + 1
        peak = max(peak, sum(active.values()))
        tenant_peaks[org] = max(tenant_peaks.get(org, 0), active[org])
        try:
            await release.wait()
        finally:
            active[org] -= 1
        return {"org": org}

    runtime = _runtime(
        store, {"analyst": handler}, worker_count=4, global_limit=3, per_org_limit=2
    )
    runner = asyncio.create_task(runtime.run())
    try:
        await _until(lambda: sum(active.values()) == 3)
        assert active == {"org-a": 2, "org-b": 1}
        await asyncio.sleep(0.1)
        assert (
            sum(
                store.get_job(task.org_id, task.task_id).status == "running"
                for task in tasks
            )
            == 3
        )
        release.set()
        await _until(
            lambda: all(
                store.get_job(task.org_id, task.task_id).status == "completed"
                for task in tasks
            )
        )
    finally:
        release.set()
        await _stop(runtime, runner)
    assert peak == 3
    assert max(tenant_peaks.values()) <= 2


def test_registry_rejects_sync_callbacks(store: SchedulerStore) -> None:
    def sync_handler(_context: JobContext) -> JsonValue:
        return {"invalid": True}

    with pytest.raises(TypeError, match="async function"):
        SchedulerRuntime(store, {"analyst": sync_handler})  # pyright: ignore[reportArgumentType]
