"""Structured help-request admission, shared evidence and ownership visibility."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from terminus.orchestration.collaboration import (
    MAX_HELP_PER_TASK,
    CollaborationRejectedError,
)
from terminus.orchestration.coordination import (
    CoordinationLimitError,
    CoordinationService,
)
from terminus.orchestration.coordination_models import (
    HelpRequestSpec,
    IncidentObjective,
)
from terminus.orchestration.models import Task
from terminus.orchestration.storage import OrchestrationNotFoundError
from terminus.storage.db import Database
from tests.test_coordination import _claim, _tasks
from tests.test_coordination_api import api  # noqa: F401


@pytest.fixture
def service(tmp_path: Path) -> Iterator[CoordinationService]:
    db = Database(str(tmp_path / "collab.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
    for org, incident in (
        ("a", "incident-a"),
        ("a", "incident-a2"),
        ("b", "incident-b"),
    ):
        db.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,"
            "summary,recommended_actions,policy_tier,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (incident, org, f"alert-{incident}", "high", "high", "F", "[]", "standard", now),
        )
    yield CoordinationService(db)
    db.close()


def _spec(**changes: Any) -> HelpRequestSpec:
    return HelpRequestSpec.model_validate(
        {
            "target_role": "network",
            "objective": "Review the beacon traffic",
            "expected_evidence_kinds": ["flow_summary"],
            **changes,
        }
    )


async def _ready(service: CoordinationService) -> Task:
    service.start_incident(
        "a",
        "incident-a",
        IncidentObjective.model_validate(
            {
                "objective": "Inspect",
                "areas": ["alert_handling", "investigation"],
                "idempotency_key": "k",
            }
        ),
    )
    main = _claim(service, "main_orchestrator")
    service.scheduler.complete(
        main.lease, await service.handlers()["main_orchestrator"](main)
    )
    for _ in range(2):
        area = _claim(service, "area_orchestrator")
        service.scheduler.complete(
            area.lease, await service.handlers()["area_orchestrator"](area)
        )
    return next(t for t in _tasks(service) if t.role == "triage")


def _evidence(service: CoordinationService, task_id: str, org: str = "a") -> str:
    return service.records.create_evidence(
        org, task_id, "fixture", datetime.now(UTC), content={"k": "v"}
    ).evidence_id


def _peer(service: CoordinationService, delegated_id: object) -> Task:
    return next(t for t in _tasks(service) if t.parent_task_id == delegated_id)


async def _run_help_area(service: CoordinationService, delegated_id: object) -> None:
    area = _claim(service, "area_orchestrator")
    assert area.task.task_id == delegated_id
    service.scheduler.complete(
        area.lease, await service.handlers()["area_orchestrator"](area)
    )


@pytest.mark.asyncio
async def test_valid_request_shares_evidence_and_peer_sees_linkage(service) -> None:
    triage = await _ready(service)
    evidence_id = _evidence(service, triage.task_id)
    view = service.request_help(
        "a", triage.task_id, _spec(shared_evidence_ids=[evidence_id])
    )
    assert view["duplicate"] is False
    assert view["state"] == "assigned"
    assert view["requester_role"] == "triage"
    assert view["requester_area"] == "alert_handling"
    assert view["responsible_area"] == "investigation"
    assert view["shared_evidence_ids"] == [evidence_id]
    await _run_help_area(service, view["delegated_task_id"])
    peer = _peer(service, view["delegated_task_id"])
    for task_id in (view["delegated_task_id"], peer.task_id):
        context = service.get_help_context("a", task_id)
        assert [e["evidence_id"] for e in context["shared_evidence"]] == [evidence_id]
        assert context["expected_evidence_kinds"] == ["flow_summary"]
    own = service.collaboration.ownership("a", view["help_request_id"])
    assert own["peer_task_id"] == peer.task_id
    with pytest.raises(OrchestrationNotFoundError):
        service.get_help_context("a", triage.task_id)
    with pytest.raises(OrchestrationNotFoundError):
        service.get_help_context("b", peer.task_id)


@pytest.mark.asyncio
async def test_duplicate_is_idempotent_even_with_whitespace_and_case(service) -> None:
    triage = await _ready(service)
    first = service.request_help("a", triage.task_id, _spec())
    again = service.request_help(
        "a", triage.task_id, _spec(objective="  review THE beacon   traffic ")
    )
    assert again["duplicate"] is True
    assert again["help_request_id"] == first["help_request_id"]
    assert again["delegated_task_id"] == first["delegated_task_id"]
    assert len(service.records.list_help_requests("a", task_id=triage.task_id)) == 1


@pytest.mark.asyncio
async def test_per_task_cap_and_incident_cap(service) -> None:
    triage = await _ready(service)
    for i in range(MAX_HELP_PER_TASK):
        _ = service.request_help("a", triage.task_id, _spec(objective=f"Question {i}"))
    with pytest.raises(CoordinationLimitError):
        service.request_help("a", triage.task_id, _spec(objective="One too many"))
    for i in range(16 - MAX_HELP_PER_TASK):
        _ = service.records.create_help_request(
            "a", triage.task_id, "network", f"legacy {i}"
        )
    with pytest.raises(CoordinationLimitError):
        service.request_help(
            "a", triage.task_id, _spec(target_role="identity", objective="Another")
        )


@pytest.mark.asyncio
async def test_self_recursive_noncore_and_unselected_are_rejected(service) -> None:
    triage = await _ready(service)
    with pytest.raises(CollaborationRejectedError) as exc:
        service.request_help("a", triage.task_id, _spec(target_role="triage"))
    assert exc.value.code == "self_delegation"
    with pytest.raises(CollaborationRejectedError) as exc:
        service.request_help("a", triage.task_id, _spec(target_role="application_api"))
    assert exc.value.code == "area_not_selected"
    for role in ("malware", "main_orchestrator", "area_orchestrator"):
        with pytest.raises(ValidationError):
            _spec(target_role=role)
    for extra in ({"tool": "x"}, {"model": "m"}, {"org_id": "b"}, {"scope": "all"}):
        with pytest.raises(ValidationError):
            _spec(**extra)
    assert not service.records.list_help_requests("a", task_id=triage.task_id)
    view = service.request_help("a", triage.task_id, _spec())
    await _run_help_area(service, view["delegated_task_id"])
    peer = _peer(service, view["delegated_task_id"])
    with pytest.raises(CollaborationRejectedError) as exc:
        service.request_help("a", peer.task_id, _spec(target_role="identity"))
    assert exc.value.code == "recursive_delegation"


@pytest.mark.asyncio
async def test_foreign_and_missing_references_are_indistinguishable(service) -> None:
    triage = await _ready(service)
    foreign_task = service.records.create_incident_task(
        "b", "incident-b", "x", "triage", "Other tenant"
    )
    other_incident = service.records.create_incident_task(
        "a", "incident-a2", "x", "triage", "Other incident"
    )
    errors = []
    for evidence_id in (
        _evidence(service, foreign_task.task_id, "b"),
        _evidence(service, other_incident.task_id),
        "missing-evidence",
    ):
        with pytest.raises(OrchestrationNotFoundError) as exc:
            service.request_help(
                "a", triage.task_id, _spec(shared_evidence_ids=[evidence_id])
            )
        errors.append(str(exc.value))
    for task_id in (foreign_task.task_id, "missing-task"):
        with pytest.raises(OrchestrationNotFoundError) as exc:
            service.request_help("a", task_id, _spec())
        errors.append(str(exc.value))
    assert len(set(errors)) == 1
    assert not service.records.list_help_requests("a", task_id=triage.task_id)


@pytest.mark.asyncio
async def test_tree_shows_cross_area_ownership(service) -> None:
    triage = await _ready(service)
    view = service.request_help("a", triage.task_id, _spec())
    tree = service.get_incident_tree("a", "incident-a")

    def walk(node: Any) -> Iterator[Any]:
        yield node
        for child in node["children"]:
            yield from walk(child)

    node = next(n for n in walk(tree["roots"][0]) if n["task_id"] == triage.task_id)
    (own,) = node["help_ownership"]
    assert own["requester_area"] == "alert_handling"
    assert own["responsible_area"] == "investigation"
    assert own["delegated_task_id"] == view["delegated_task_id"]
    assert own["state"] == "assigned"
    assert own["reason_code"] is None


@pytest.mark.asyncio
async def test_failed_peer_is_rejected_never_resolved(service) -> None:
    triage = await _ready(service)
    view = service.request_help("a", triage.task_id, _spec())
    await _run_help_area(service, view["delegated_task_id"])
    peer = _peer(service, view["delegated_task_id"])
    while (ctx := _claim(service, "network")).task.task_id != peer.task_id:
        service.scheduler.complete(ctx.lease, {"finding": "other"})
    service.scheduler.fail(ctx.lease, "boom", retryable=False)
    assert service.reconcile_help("a", view["help_request_id"]).status == "assigned"
    own = service.collaboration.ownership("a", view["help_request_id"])
    assert own["state"] == "rejected"
    assert own["reason_code"] == "peer_failed"


@pytest.mark.asyncio
async def test_parallel_identical_requests_create_one_task(service) -> None:
    triage = await _ready(service)
    row = service.db.fetchone("PRAGMA database_list")
    assert row is not None
    path = row["file"]
    results: list[str] = []
    errors: list[BaseException] = []

    def worker() -> None:
        db = Database(path)
        try:
            svc = CoordinationService(db)
            view = svc.request_help("a", triage.task_id, _spec())
            results.append(view["help_request_id"])
        except BaseException as exc:
            errors.append(exc)
        finally:
            db.close()

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(set(results)) == 1
    helps = [
        t for t in _tasks(service) if (t.idempotency_key or "").startswith("coord:help:")
    ]
    assert len(helps) == 1


def test_http_contract_is_strict_and_hides_missing_or_foreign(api) -> None:  # noqa: F811
    from tests.test_coordination_api import _headers

    client, store = api
    task = store.create_incident_task("org-b", "incident-b", "x", "triage", "B task")
    body = {"target_role": "network", "objective": "Look"}
    path = f"/orchestration/tasks/{task.task_id}/help-requests"
    foreign = client.post(path, json=body, headers=_headers())
    missing = client.post(
        "/orchestration/tasks/nope/help-requests", json=body, headers=_headers()
    )
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    for bad in ({**body, "tool": "x"}, {**body, "target_role": "malware"}):
        resp = client.post(path, json=bad, headers=_headers())
        assert resp.status_code == 400
    assert client.post(path, json=body, headers=_headers("viewer")).status_code == 403
    ctx = client.get(
        f"/orchestration/tasks/{task.task_id}/help-context", headers=_headers()
    )
    assert ctx.status_code == 404
