"""Durable delegation, real runtime wiring, bounds and honest aggregate states."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import JsonValue, ValidationError

from terminus.orchestration.coordination import (
    MAX_INCIDENT_TASKS,
    CoordinationLimitError,
    CoordinationRoleError,
    CoordinationService,
)
from terminus.orchestration.coordination_models import (
    IncidentObjective,
    SpecialistDefinition,
)
from terminus.orchestration.scheduler import JobContext, SchedulerRuntime
from terminus.orchestration.scheduler_store import SchedulerLeaseError
from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
)
from terminus.storage.db import Database


@pytest.fixture
def service(tmp_path: Path) -> Iterator[CoordinationService]:
    db = Database(str(tmp_path / "coordination.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
        db.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                f"incident-{org}",
                org,
                f"alert-{org}",
                "high",
                "high",
                "Fixture",
                "[]",
                "standard",
                now,
            ),
        )
    yield CoordinationService(db)
    db.close()


def _request(**updates: object) -> IncidentObjective:
    return IncidentObjective.model_validate(
        {
            "objective": "Inspect fixture evidence",
            "areas": ["investigation"],
            "idempotency_key": "start-1",
            **updates,
        }
    )


async def _noop() -> None:
    pass


def _claim(service: CoordinationService, role: str) -> JobContext:
    store = service.scheduler
    if not store._coordinators:
        assert store.acquire_coordinator("test-owner", lease_seconds=300)
    lease = store.claim_next("test-owner", "test-worker", [role], lease_seconds=300)
    assert lease is not None
    # The isolated transaction tests deliberately bypass the async checkpoint to
    # prove that the inner durable fence alone prevents stale mutations.
    return cast(
        "JobContext", SimpleNamespace(task=lease.task, lease=lease, checkpoint=_noop)
    )


def _tasks(service: CoordinationService):
    return service.records.list_tasks("a", incident_id="incident-a", limit=200)


def _runtime(service: CoordinationService, handlers=None) -> SchedulerRuntime:
    return SchedulerRuntime(
        service.scheduler,
        handlers or service.handlers(),
        worker_count=1,
        global_limit=1,
        per_org_limit=1,
        poll_interval=0.01,
        heartbeat_interval=0.05,
        coordinator_lease_seconds=1,
        job_lease_seconds=1,
    )


async def _until(condition) -> None:
    async with asyncio.timeout(5):
        while not condition():  # noqa: ASYNC110 - observe committed runtime state
            await asyncio.sleep(0.01)


def test_strict_explicit_objective_and_catalog(service: CoordinationService) -> None:
    for changes in (
        {"areas": []},
        {"areas": ["investigation", "investigation"]},
        {"areas": ["unknown"]},
        {"priority": True},
        {"objective": "  "},
        {"extra": 1},
    ):
        with pytest.raises(ValidationError):
            _request(**changes)
    with pytest.raises(CoordinationRoleError):
        CoordinationService(
            service.db,
            catalog=[
                SpecialistDefinition(role="main_orchestrator", area="investigation")
            ],
        )
    with pytest.raises(CoordinationLimitError):
        CoordinationService(service.db, catalog=[])


def test_start_is_atomic_idempotent_tenant_scoped_and_opt_in(
    service: CoordinationService, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (
        service.get_incident_tree("a", "incident-a")["aggregate_status"]
        == "not_started"
    )
    with pytest.raises(OrchestrationNotFoundError):
        service.start_incident("b", "incident-a", _request())
    original = service.scheduler.enqueue_task

    def fail(*args, **kwargs):
        raise RuntimeError("admission failure")

    monkeypatch.setattr(service.scheduler, "enqueue_task", fail)
    with pytest.raises(RuntimeError, match="admission failure"):
        service.start_incident("a", "incident-a", _request())
    assert _tasks(service) == []
    monkeypatch.setattr(service.scheduler, "enqueue_task", original)
    root = service.start_incident("a", "incident-a", _request())
    assert service.start_incident("a", "incident-a", _request()) == root
    service.db.close()
    reopened = CoordinationService(Database(service.db.db_path))
    assert reopened.start_incident("a", "incident-a", _request()) == root
    assert len(_tasks(reopened)) == 1
    assert reopened.scheduler.get_job("a", root.task_id).status == "queued"
    with pytest.raises(OrchestrationConflictError):
        reopened.start_incident("a", "incident-a", _request(idempotency_key="new"))
    with pytest.raises(OrchestrationNotFoundError):
        reopened.get_incident_tree("b", "incident-a")
    reopened.db.close()


@pytest.mark.asyncio
async def test_atomic_fanout_survives_failure_retry_and_restart(
    service: CoordinationService, monkeypatch: pytest.MonkeyPatch
) -> None:
    service.start_incident(
        "a", "incident-a", _request(areas=["alert_handling", "investigation"])
    )
    context = _claim(service, "main_orchestrator")
    original = service.scheduler.enqueue_task
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("crash during fanout")
        return original(*args, **kwargs)

    monkeypatch.setattr(service.scheduler, "enqueue_task", fail_second)
    with pytest.raises(RuntimeError, match="crash during fanout"):
        await service.handlers()["main_orchestrator"](context)
    assert len(_tasks(service)) == 1
    assert len(service.scheduler.list_jobs("a")) == 1
    monkeypatch.setattr(service.scheduler, "enqueue_task", original)
    first = await service.handlers()["main_orchestrator"](context)
    reopened = CoordinationService(service.db)
    second = await reopened.handlers()["main_orchestrator"](context)
    assert first == second
    assert len(_tasks(service)) == 3
    service.scheduler.complete(context.lease, first)
    area = _claim(service, "area_orchestrator")
    first_area = await service.handlers()["area_orchestrator"](area)
    assert await reopened.handlers()["area_orchestrator"](area) == first_area
    assert len({task.task_id for task in _tasks(service)}) == len(_tasks(service))


@pytest.mark.asyncio
async def test_fence_and_cancellation_prevent_fanout_after_checkpoint(
    service: CoordinationService,
) -> None:
    service.start_incident("a", "incident-a", _request())
    context = _claim(service, "main_orchestrator")
    service.scheduler.request_cancel("a", context.task.task_id)
    with pytest.raises(SchedulerLeaseError):
        await service.handlers()["main_orchestrator"](context)
    assert len(_tasks(service)) == 1
    service.db.execute("DELETE FROM orchestration_scheduler_coordinator")
    with pytest.raises(SchedulerLeaseError):
        await service.handlers()["main_orchestrator"](context)
    assert len(_tasks(service)) == 1


@pytest.mark.asyncio
async def test_five_lazy_areas_and_unavailable_specialty_gaps(
    service: CoordinationService,
) -> None:
    request = _request(
        areas=[
            "alert_handling",
            "investigation",
            "infrastructure",
            "applications_data",
            "response_improvement",
        ]
    )
    root = service.start_incident("a", "incident-a", request)
    assert len(_tasks(service)) == 1
    runtime = _runtime(service)
    runner = asyncio.create_task(runtime.run())
    try:
        await _until(
            lambda: (
                len(_tasks(service)) == 13
                and all(
                    task.status == "completed"
                    for task in _tasks(service)
                    if task.role.endswith("orchestrator")
                )
            )
        )
        assert service.records.get_task("a", root.task_id).status == "completed"
        assert {
            task.role
            for task in _tasks(service)
            if not task.role.endswith("orchestrator")
        } == {
            "triage",
            "identity",
            "endpoint",
            "network",
            "response_planner",
            "verification",
            "evidence_reporting",
        }
        tree = service.get_incident_tree("a", "incident-a")
        node = tree["roots"][0]
        empty = [
            child
            for child in node["children"]
            if child["area"] in {"infrastructure", "applications_data"}
        ]
        assert all(
            child["aggregate_status"] == "incomplete" and child["gaps"]
            for child in empty
        )
        assert tree["aggregate_status"] != "completed"
        assert tree["incident_closed"] is False
    finally:
        await runtime.stop()
        await runner


@pytest.mark.asyncio
async def test_single_worker_executes_specialist_and_preserves_real_evidence(
    service: CoordinationService,
) -> None:
    service.start_incident("a", "incident-a", _request(areas=["alert_handling"]))

    async def specialist(context: JobContext) -> JsonValue:
        await context.checkpoint()
        evidence = service.records.create_evidence(
            "a",
            context.task.task_id,
            "fixture",
            datetime.now(UTC),
            content={"observed": "one event"},
        )
        return {
            "evidence_ids": [evidence.evidence_id],
            "finding": "Fixture event observed",
        }

    runtime = _runtime(service, {**service.handlers(), "triage": specialist})
    runner = asyncio.create_task(runtime.run())
    try:
        await _until(
            lambda: (
                service.get_incident_tree("a", "incident-a")["aggregate_status"]
                == "completed"
            )
        )
        tree = service.get_incident_tree("a", "incident-a")
        leaf = tree["roots"][0]["children"][0]["children"][0]
        assert leaf["runs"][0]["result"]["evidence_ids"] == [
            leaf["evidence"][0]["evidence_id"]
        ]
        assert tree["incident_closed"] is False
    finally:
        await runtime.stop()
        await runner
    reopened = CoordinationService(Database(service.db.db_path))
    assert (
        reopened.get_incident_tree("a", "incident-a")["aggregate_status"] == "completed"
    )
    reopened.db.close()


@pytest.mark.asyncio
async def test_help_routes_through_area_and_requires_completed_child(
    service: CoordinationService,
) -> None:
    service.start_incident("a", "incident-a", _request(areas=["alert_handling"]))
    main = _claim(service, "main_orchestrator")
    service.scheduler.complete(
        main.lease, await service.handlers()["main_orchestrator"](main)
    )
    area = _claim(service, "area_orchestrator")
    service.scheduler.complete(
        area.lease, await service.handlers()["area_orchestrator"](area)
    )
    triage = next(task for task in _tasks(service) if task.role == "triage")
    request = service.records.create_help_request(
        "a", triage.task_id, "network", "Review fixture network event"
    )
    delegated = service.assign_help("a", request.help_request_id)
    assert delegated.area == "investigation"
    assert delegated.role == "area_orchestrator"
    assert not any(task.role == "network" for task in _tasks(service))
    assert service.assign_help("a", request.help_request_id) == delegated
    assert service.reconcile_help("a", request.help_request_id).status == "assigned"
    area_help = _claim(service, "area_orchestrator")
    service.scheduler.complete(
        area_help.lease, await service.handlers()["area_orchestrator"](area_help)
    )
    assert service.reconcile_help("a", request.help_request_id).status == "assigned"
    network = _claim(service, "network")
    service.scheduler.complete(network.lease, {"finding": "Fixture reviewed"})
    assert service.reconcile_help("a", request.help_request_id).status == "resolved"
    unknown = service.records.create_help_request(
        "a", triage.task_id, "malware", "Needs unavailable role"
    )
    with pytest.raises(CoordinationRoleError):
        service.assign_help("a", unknown.help_request_id)
    assert (
        service.records.get_help_request("a", unknown.help_request_id).status == "open"
    )
    with pytest.raises(OrchestrationNotFoundError):
        service.assign_help("b", request.help_request_id)


@pytest.mark.asyncio
async def test_bounds_and_missing_delegation_are_honest(
    service: CoordinationService,
) -> None:
    root = service.start_incident(
        "a", "incident-a", _request(areas=["alert_handling", "investigation"])
    )
    for i in range(MAX_INCIDENT_TASKS - 2):
        service.records.create_incident_task(
            "a", "incident-a", "fixture", "fixture", f"Imported {i}"
        )
    context = _claim(service, "main_orchestrator")
    with pytest.raises(CoordinationLimitError):
        await service.handlers()["main_orchestrator"](context)
    assert len(_tasks(service)) == MAX_INCIDENT_TASKS - 1
    service.scheduler.complete(context.lease, {"delegation_only": True})
    tree = service.get_incident_tree("a", "incident-a")
    assert tree["aggregate_status"] == "incomplete"
    assert "Planned area delegation is missing" in tree["gaps"]
    assert tree["roots"][0]["task_id"] == root.task_id
    assert tree["roots"][0]["children"] == []
    for i in range(2):
        service.records.create_incident_task(
            "a", "incident-a", "fixture", "fixture", f"Overflow {i}"
        )
    with pytest.raises(CoordinationLimitError):
        service.get_incident_tree("a", "incident-a")


@pytest.mark.asyncio
async def test_help_bound_is_per_incident_even_after_repeated_assignment(
    service: CoordinationService,
) -> None:
    service.start_incident("a", "incident-a", _request(areas=["alert_handling"]))
    main = _claim(service, "main_orchestrator")
    service.scheduler.complete(
        main.lease, await service.handlers()["main_orchestrator"](main)
    )
    area = _claim(service, "area_orchestrator")
    service.scheduler.complete(
        area.lease, await service.handlers()["area_orchestrator"](area)
    )
    triage = next(task for task in _tasks(service) if task.role == "triage")
    for i in range(16):
        request = service.records.create_help_request(
            "a", triage.task_id, "network", f"Question {i}"
        )
        assigned = service.assign_help("a", request.help_request_id)
        assert service.assign_help("a", request.help_request_id) == assigned
    request = service.records.create_help_request(
        "a", triage.task_id, "network", "One too many"
    )
    with pytest.raises(CoordinationLimitError):
        service.assign_help("a", request.help_request_id)
    assert (
        service.records.get_help_request("a", request.help_request_id).status == "open"
    )


@pytest.mark.asyncio
async def test_optional_application_specialty_requires_explicit_enable(
    service: CoordinationService,
) -> None:
    enabled = CoordinationService(service.db, enable_application_api=True)
    enabled.start_incident("a", "incident-a", _request(areas=["applications_data"]))
    main = _claim(enabled, "main_orchestrator")
    enabled.scheduler.complete(
        main.lease, await enabled.handlers()["main_orchestrator"](main)
    )
    area = _claim(enabled, "area_orchestrator")
    await enabled.handlers()["area_orchestrator"](area)
    assert {task.role for task in _tasks(enabled)} == {
        "main_orchestrator",
        "area_orchestrator",
        "application_api",
    }


@pytest.mark.asyncio
async def test_expired_lease_at_commit_rolls_back_children(
    service: CoordinationService, monkeypatch: pytest.MonkeyPatch
) -> None:
    service.start_incident("a", "incident-a", _request())
    context = _claim(service, "main_orchestrator")
    original = service.scheduler.enqueue_task

    def expire_after_admission(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr(
            service.scheduler, "clock", lambda: datetime.now(UTC) + timedelta(hours=1)
        )
        return result

    monkeypatch.setattr(service.scheduler, "enqueue_task", expire_after_admission)
    with pytest.raises(SchedulerLeaseError):
        await service.handlers()["main_orchestrator"](context)
    assert len(_tasks(service)) == 1
    assert len(service.scheduler.list_jobs("a")) == 1


@pytest.mark.asyncio
async def test_runtime_restart_continues_durable_specialist_queue(
    service: CoordinationService,
) -> None:
    root = service.start_incident("a", "incident-a", _request())
    runtime = _runtime(service)
    runner = asyncio.create_task(runtime.run())
    try:
        await _until(
            lambda: (
                len(_tasks(service)) == 5
                and all(
                    task.status == "completed"
                    for task in _tasks(service)
                    if task.role.endswith("orchestrator")
                )
            )
        )
    finally:
        await runtime.stop()
        await runner
    original_ids = {task.task_id for task in _tasks(service)}
    service.db.close()
    reopened = CoordinationService(Database(service.db.db_path))

    async def fixture_specialist(context: JobContext) -> JsonValue:
        await context.checkpoint()
        return {"fixture_result": context.task.role}

    runtime = _runtime(
        reopened,
        {
            **reopened.handlers(),
            "identity": fixture_specialist,
            "endpoint": fixture_specialist,
            "network": fixture_specialist,
        },
    )
    runner = asyncio.create_task(runtime.run())
    try:
        await _until(
            lambda: (
                reopened.get_incident_tree("a", "incident-a")["aggregate_status"]
                == "completed"
            )
        )
        assert {task.task_id for task in _tasks(reopened)} == original_ids
        assert reopened.records.get_task("a", root.task_id).status == "completed"
        runs = reopened.records.list_agent_runs("a", incident_id="incident-a")
        assert len(runs) == 5
        assert (
            sum(bool(run.result and "fixture_result" in run.result) for run in runs)
            == 3
        )
    finally:
        await runtime.stop()
        await runner
        reopened.db.close()
