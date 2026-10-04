"""SQLite ownership, admission, retry and reconciliation safety boundaries."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import ValidationError

from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
)
from terminus.orchestration.scheduler_models import SchedulerJob
from terminus.orchestration.scheduler_store import SchedulerLeaseError, SchedulerStore
from terminus.storage.db import Database


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 4, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def store(tmp_path: Path):
    db = Database(str(tmp_path / "scheduler.db"))
    clock = Clock()
    for org in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, clock.now.isoformat()),
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
                clock.now.isoformat(),
            ),
        )
    scheduler = SchedulerStore(db, clock=clock)
    yield scheduler, clock
    db.close()


def task(
    store: SchedulerStore, org: str = "a", *, role: str = "analyst", priority: int = 100
):
    return store.records.create_incident_task(
        org, f"incident-{org}", "triage", role, "Inspect incident", priority=priority
    )


def admit(store: SchedulerStore, org: str = "a", *, max_attempts: int = 3, **kwargs):
    record = task(store, org, **kwargs)
    return store.enqueue_task(org, record.task_id, max_attempts=max_attempts)


def claim(store: SchedulerStore, worker: str = "worker", **kwargs):
    return store.claim_next("coordinator", worker, {"analyst"}, **kwargs)


def uncertain_action(store: SchedulerStore, task_id: str, status: str = "unknown"):
    action = store.records.create_action_attempt(
        "a", task_id, "test-action", ["test-host"]
    )
    for before, after in (("proposed", "approved"), ("approved", "dispatched")):
        action = store.records.transition_action_attempt(
            "a", action.attempt_id, before, after, actor="test-operator"
        )
    if status == "dispatched":
        return action
    return store.records.transition_action_attempt(
        "a",
        action.attempt_id,
        "dispatched",
        status,
        actor="test-operator",
        outputs={"ack": "test"} if status == "acknowledged" else None,
        error="Test outcome unknown" if status == "unknown" else None,
    )


def test_explicit_idempotent_tenant_scoped_admission(store):
    scheduler, _ = store
    record = task(scheduler)
    scheduler.acquire_coordinator("coordinator")
    assert claim(scheduler) is None
    job = scheduler.enqueue_task("a", record.task_id)
    assert scheduler.enqueue_task("a", record.task_id) == job
    with pytest.raises(OrchestrationConflictError):
        scheduler.enqueue_task("a", record.task_id, max_attempts=2)
    with pytest.raises(OrchestrationNotFoundError):
        scheduler.enqueue_task("b", record.task_id)
    assert scheduler.list_jobs("b") == []
    legacy = scheduler.records.create_task(
        "a", "nonexistent", "triage", "analyst", "Legacy"
    )
    with pytest.raises(OrchestrationNotFoundError):
        scheduler.enqueue_task("a", legacy.task_id)
    assert claim(scheduler).task_id == record.task_id


def test_priority_fifo_registered_roles_and_limits(store):
    scheduler, _ = store
    unknown = admit(scheduler, role="unsupported", priority=1000)
    low = admit(scheduler, priority=1)
    first = admit(scheduler, priority=900)
    second = admit(scheduler, priority=900)
    other = admit(scheduler, "b", priority=100)
    scheduler.acquire_coordinator("coordinator")
    assert (
        claim(scheduler, "worker-1", global_limit=3, per_org_limit=2).task_id
        == first.task_id
    )
    assert (
        claim(scheduler, "worker-2", global_limit=3, per_org_limit=2).task_id
        == second.task_id
    )
    assert (
        claim(scheduler, "worker-3", global_limit=3, per_org_limit=2).task_id
        == other.task_id
    )
    assert claim(scheduler, "worker-4", global_limit=3, per_org_limit=2) is None
    assert scheduler.get_job("a", low.task_id).status == "queued"
    assert scheduler.get_job("a", unknown.task_id).status == "queued"
    assert scheduler.records.list_agent_runs("a", task_id=unknown.task_id) == []


@pytest.mark.parametrize(
    ("job_count", "global_limit", "per_org_limit", "expected_claims"),
    [(4, 1, 2, 1), (1, 4, 2, 1), (4, 4, 1, 1), (4, 4, 2, 2)],
)
def test_separate_connections_race_claim_with_limits(
    store, job_count, global_limit, per_org_limit, expected_claims
):
    scheduler, _ = store
    admitted = [admit(scheduler) for _ in range(job_count)]
    scheduler.acquire_coordinator("coordinator")
    barrier = Barrier(4)

    def compete(index: int):
        try:
            connection_id = id(scheduler.db._get_connection())
            barrier.wait(timeout=10)
            lease = claim(
                scheduler,
                f"worker-{index}",
                global_limit=global_limit,
                per_org_limit=per_org_limit,
            )
            return connection_id, lease
        finally:
            scheduler.db.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(compete, range(4)))
    assert len({connection_id for connection_id, _ in results}) == 4
    leases = [lease for _, lease in results if lease is not None]
    assert len(leases) == expected_claims
    assert {lease.task_id for lease in leases} == {
        job.task_id for job in admitted[:expected_claims]
    }
    assert len(scheduler.records.list_agent_runs("a")) == expected_claims
    assert len(scheduler.list_jobs("a", status="running")) == expected_claims


def test_coordinator_race_and_old_owner_cannot_release_replacement(store):
    scheduler, clock = store
    barrier = Barrier(2)

    def compete(index: int):
        db = Database(scheduler.db.db_path)
        candidate = SchedulerStore(db, clock=clock)
        try:
            barrier.wait(timeout=10)
            return candidate.acquire_coordinator(f"owner-{index}", lease_seconds=1)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(compete, range(2)))
    winners = [lease for lease in results if lease is not None]
    assert len(winners) == 1
    clock.advance(1)
    replacement = scheduler.acquire_coordinator(winners[0].owner_id)
    assert replacement is not None
    assert replacement.lease_token != winners[0].lease_token
    assert scheduler.release_coordinator(winners[0]) is False
    with pytest.raises(SchedulerLeaseError):
        scheduler.renew_coordinator(winners[0])
    assert scheduler.release_coordinator(replacement) is True


def test_replaced_coordinator_fences_live_worker_and_cannot_be_forged(store):
    scheduler, clock = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator", lease_seconds=1)
    lease = claim(scheduler, lease_seconds=30)
    clock.advance(1)
    replacement_db = Database(scheduler.db.db_path)
    replacement = SchedulerStore(replacement_db, clock=clock)
    try:
        assert replacement.acquire_coordinator("coordinator") is not None
        for publish in (
            lambda: scheduler.complete(lease, {"late": True}),
            lambda: scheduler.fail(lease, "late failure"),
            lambda: scheduler.heartbeat(lease),
            lambda: scheduler.cancel(lease),
        ):
            with pytest.raises(SchedulerLeaseError):
                publish()
        assert replacement.records.get_agent_run("a", lease.run_id).status == "running"
        assert replacement.get_job("a", job.task_id).status == "running"
        with pytest.raises(SchedulerLeaseError):
            claim(scheduler)
    finally:
        replacement_db.close()


def test_expired_worker_cannot_publish_and_restart_preserves_retry_budget(store):
    scheduler, clock = store
    job = admit(scheduler, max_attempts=2)
    scheduler.acquire_coordinator("coordinator", lease_seconds=1)
    first = claim(scheduler, lease_seconds=1)
    clock.advance(1)
    with pytest.raises(SchedulerLeaseError):
        scheduler.complete(first, {"late": True})
    scheduler.db.close()
    restarted_db = Database(scheduler.db.db_path)
    restarted = SchedulerStore(restarted_db, clock=clock)
    try:
        restarted.acquire_coordinator("coordinator", lease_seconds=60)
        recovered = restarted.recover_expired("coordinator")
        assert len(recovered) == 1
        assert recovered[0].status == "retry_wait"
        assert recovered[0].attempt == 1
        assert recovered[0].available_at == clock.now + timedelta(seconds=5)
        assert restarted.records.get_agent_run("a", first.run_id).status == "failed"
        assert claim(restarted) is None
        clock.advance(5)
        second = claim(restarted, lease_seconds=1)
        assert second is not None
        assert second.attempt == 2
        assert second.lease_token != first.lease_token
        with pytest.raises(SchedulerLeaseError):
            restarted.complete(first, {"old": True})
        clock.advance(1)
        exhausted = restarted.recover_expired("coordinator")
        assert exhausted[0].status == "failed"
        assert exhausted[0].attempt == 2
        clock.advance(10)
        assert claim(restarted) is None
        assert restarted.records.get_task("a", job.task_id).status == "failed"
        assert len(restarted.records.list_agent_runs("a", task_id=job.task_id)) == 2
    finally:
        restarted_db.close()


def test_subsecond_retry_and_expiry_comparisons(store):
    scheduler, clock = store
    clock.advance(0.000001)
    admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler, lease_seconds=0.000001)
    assert lease is not None
    clock.advance(0.000001)
    assert scheduler.recover_expired("coordinator")[0].status == "retry_wait"


@pytest.mark.parametrize("status", ["dispatched", "acknowledged", "unknown"])
def test_uncertain_actions_hold_admission_and_cancellation(store, status):
    scheduler, _ = store
    job = admit(scheduler)
    uncertain_action(scheduler, job.task_id, status)
    scheduler.acquire_coordinator("coordinator")
    assert claim(scheduler) is None
    held = scheduler.get_job("a", job.task_id)
    assert held.status == "waiting"
    assert held.attempt == 0
    assert held.lease_token is None
    assert scheduler.records.get_task("a", job.task_id).status == "waiting"
    assert scheduler.request_cancel("a", job.task_id).status == "waiting"
    assert claim(scheduler) is None


def test_uncertain_outcome_after_running_lease_blocks_retry_and_success(store):
    scheduler, clock = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler, lease_seconds=1)
    uncertain_action(scheduler, job.task_id)
    clock.advance(1)
    assert scheduler.recover_expired("coordinator")[0].status == "waiting"
    assert scheduler.get_job("a", job.task_id).attempt == 1
    assert claim(scheduler) is None
    assert scheduler.records.get_agent_run("a", lease.run_id).status == "failed"

    another = admit(scheduler)
    second = claim(scheduler)
    uncertain_action(scheduler, another.task_id)
    assert scheduler.complete(second, {"handler_returned": True}).status == "waiting"
    assert scheduler.records.get_task("a", another.task_id).status == "waiting"


@pytest.mark.parametrize("status", ["verified", "failed"])
@pytest.mark.parametrize("failure", ["handler", "expiry"])
def test_action_dispatch_history_blocks_replay_after_failure(store, status, failure):
    scheduler, clock = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler, lease_seconds=1)
    action = uncertain_action(scheduler, job.task_id, "acknowledged")
    scheduler.records.transition_action_attempt(
        "a",
        action.attempt_id,
        "acknowledged",
        status,
        actor="test-operator",
        outputs={"verified": "test evidence"} if status == "verified" else None,
        error="Failure after dispatch" if status == "failed" else None,
    )
    if failure == "handler":
        held = scheduler.fail(lease, "Handler failed after an effect")
    else:
        clock.advance(1)
        held = scheduler.recover_expired("coordinator")[0]
    assert held.status == "waiting"
    assert held.recovery_reason == "Previous action dispatch prevents automatic replay"
    assert held.attempt == 1
    assert scheduler.records.get_task("a", job.task_id).status == "waiting"
    clock.advance(10)
    assert claim(scheduler) is None


def test_verified_action_can_complete_and_predispatch_failure_can_retry(store):
    scheduler, _ = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler)
    action = uncertain_action(scheduler, job.task_id, "acknowledged")
    scheduler.records.transition_action_attempt(
        "a",
        action.attempt_id,
        "acknowledged",
        "verified",
        actor="test-operator",
        outputs={"evidence": "Observed test result"},
    )
    assert scheduler.complete(lease, {"verified": True}).status == "completed"

    safe_job = admit(scheduler)
    safe_lease = claim(scheduler)
    safe_action = scheduler.records.create_action_attempt(
        "a", safe_job.task_id, "test-action", ["host"]
    )
    scheduler.records.transition_action_attempt(
        "a",
        safe_action.attempt_id,
        "proposed",
        "rejected",
        actor="test-operator",
    )
    assert (
        scheduler.fail(safe_lease, "Handler failed before dispatch").status
        == "retry_wait"
    )


@pytest.mark.parametrize("status", ["verified", "failed"])
def test_admission_does_not_replay_existing_dispatched_action(store, status):
    scheduler, _ = store
    job = admit(scheduler)
    action = uncertain_action(scheduler, job.task_id, "acknowledged")
    scheduler.records.transition_action_attempt(
        "a",
        action.attempt_id,
        "acknowledged",
        status,
        actor="test-operator",
        outputs={"evidence": "Observed result"} if status == "verified" else None,
        error="Failure after dispatch" if status == "failed" else None,
    )
    scheduler.acquire_coordinator("coordinator")
    assert claim(scheduler) is None
    assert scheduler.get_job("a", job.task_id).status == "waiting"
    assert scheduler.get_job("a", job.task_id).attempt == 0
    assert scheduler.records.list_agent_runs("a", task_id=job.task_id) == []


def test_restart_preserves_uncertain_action_hold(store):
    scheduler, clock = store
    job = admit(scheduler)
    uncertain_action(scheduler, job.task_id)
    scheduler.db.close()
    reopened_db = Database(scheduler.db.db_path)
    reopened = SchedulerStore(reopened_db, clock=clock)
    try:
        reopened.acquire_coordinator("coordinator")
        assert claim(reopened) is None
        assert reopened.get_job("a", job.task_id).status == "waiting"
        assert (
            reopened.records.list_action_attempts("a", task_id=job.task_id)[0].status
            == "unknown"
        )
        assert reopened.records.list_agent_runs("a", task_id=job.task_id) == []
    finally:
        reopened_db.close()


def test_cancellation_request_wins_completion_and_renewal_can_cover_grace(store):
    scheduler, clock = store
    queued = admit(scheduler)
    assert scheduler.request_cancel("a", queued.task_id).status == "cancelled"
    running = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler, lease_seconds=1)
    requested = scheduler.request_cancel("a", running.task_id)
    assert requested.status == "running"
    assert scheduler.is_cancel_requested(lease)
    with pytest.raises(SchedulerLeaseError, match="Cancellation requested"):
        scheduler.heartbeat(lease)
    renewed = scheduler.heartbeat(lease, allow_cancellation=True)
    clock.advance(2)
    assert scheduler.recover_expired("coordinator") == []
    assert scheduler.complete(renewed, {"late_success": True}).status == "cancelled"
    assert scheduler.records.get_agent_run("a", lease.run_id).result is None
    assert scheduler.records.get_task("a", running.task_id).status == "cancelled"


def test_noncooperative_execution_hold_fences_late_callback(store):
    scheduler, _ = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler)
    assert scheduler.hold(lease, "Callback suppressed cancellation").status == "waiting"
    with pytest.raises(SchedulerLeaseError):
        scheduler.complete(lease, {"late": True})
    assert claim(scheduler) is None
    assert scheduler.get_job("a", job.task_id).attempt == 1
    assert scheduler.records.get_agent_run("a", lease.run_id).status == "failed"


def test_retryable_failure_delay_and_nonretryable_failure(store):
    scheduler, clock = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator", lease_seconds=60)
    first = claim(scheduler)
    assert scheduler.fail(first, "Safe failure").status == "retry_wait"
    clock.advance(4.999999)
    assert claim(scheduler) is None
    clock.advance(0.000001)
    second = claim(scheduler)
    assert second.attempt == 2
    assert (
        scheduler.fail(second, "Terminal failure", retryable=False).status == "failed"
    )
    assert scheduler.get_job("a", job.task_id).attempt == 2
    assert claim(scheduler) is None


@pytest.mark.parametrize("stage", ["claim", "complete"])
def test_multiwrite_transaction_rolls_back_on_interruption(store, monkeypatch, stage):
    scheduler, _ = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler) if stage == "complete" else None

    def interrupt_write(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(scheduler, "_save_job", interrupt_write)
    operation = (
        (lambda: claim(scheduler))
        if stage == "claim"
        else (lambda: scheduler.complete(lease, {"ok": True}))
    )
    with pytest.raises(KeyboardInterrupt):
        operation()
    expected = "queued" if stage == "claim" else "running"
    assert scheduler.get_job("a", job.task_id).status == expected
    assert scheduler.records.get_task("a", job.task_id).status == expected
    runs = scheduler.records.list_agent_runs("a", task_id=job.task_id)
    assert len(runs) == (0 if stage == "claim" else 1)
    if runs:
        assert runs[0].status == "running"
        assert runs[0].result is None


@pytest.mark.parametrize(
    "result", [{"nested": [float("nan")]}, {"large": "x" * 262144}]
)
def test_invalid_results_leave_owned_records_unchanged(store, result):
    scheduler, _ = store
    job = admit(scheduler)
    scheduler.acquire_coordinator("coordinator")
    lease = claim(scheduler)
    with pytest.raises((ValueError, ValidationError)):
        scheduler.complete(lease, result)
    assert scheduler.get_job("a", job.task_id).status == "running"
    assert scheduler.records.get_agent_run("a", lease.run_id).status == "running"
    assert scheduler.records.get_task("a", job.task_id).status == "running"


@pytest.mark.parametrize("attempts", [0, 6, True, "3", 1.5])
def test_attempt_configuration_is_strict(store, attempts):
    scheduler, _ = store
    record = task(scheduler)
    with pytest.raises(ValueError):
        scheduler.enqueue_task("a", record.task_id, max_attempts=attempts)
    assert scheduler.list_jobs("a") == []


def test_model_times_are_normalized_and_naive_clocks_rejected(store):
    scheduler, clock = store
    job = admit(scheduler)
    local = clock.now.astimezone(timezone(timedelta(hours=3)))
    updated = SchedulerJob.model_validate(job.model_dump() | {"available_at": local})
    assert updated.available_at == clock.now
    assert updated.available_at.tzinfo == UTC
    with pytest.raises(ValidationError):
        SchedulerJob.model_validate(
            job.model_dump() | {"available_at": clock.now.replace(tzinfo=None)}
        )
    with pytest.raises(ValueError, match="aware datetime"):
        SchedulerStore(
            scheduler.db, clock=lambda: clock.now.replace(tzinfo=None)
        ).acquire_coordinator("owner")


def test_additive_schema_preserves_legacy_tables_and_singleton(tmp_path: Path):
    path = tmp_path / "legacy-scheduler.db"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE unrelated (original TEXT, custom INTEGER)")
        connection.execute("INSERT INTO unrelated VALUES('keep', 7)")
    original_instance = Database._instance
    db = Database(str(path))
    reopened = Database(str(path))
    try:
        assert Database._instance is original_instance
        assert reopened.fetchone("SELECT * FROM unrelated") == {
            "original": "keep",
            "custom": 7,
        }
        tables = {
            row["name"]
            for row in db.fetchall("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "orchestration_scheduler_jobs",
            "orchestration_scheduler_coordinator",
            "unrelated",
        } <= tables
    finally:
        db.close()
        reopened.close()
