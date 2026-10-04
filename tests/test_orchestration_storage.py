"""Durability, tenant isolation and honest lifecycle checks."""

import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from terminus.orchestration import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
    OrchestrationTransitionError,
    Task,
)
from terminus.storage.db import Database


@pytest.fixture
def store(tmp_path: Path) -> OrchestrationStore:
    db = Database(str(tmp_path / "orchestration.db"))
    for org in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, datetime.now(UTC).isoformat()),
        )
    return OrchestrationStore(db)


def make_task(
    store: OrchestrationStore, org: str = "a", incident: str = "incident-1", **kwargs
):
    return store.create_task(
        org, incident, "triage", "analyst", "Investigate alert", **kwargs
    )


def test_restart_preserves_records_and_existing_schema(store: OrchestrationStore):
    task = make_task(store)
    run = store.create_agent_run("a", task.task_id, model_name="metadata-only")
    evidence = store.create_evidence(
        "a", task.task_id, "siem", datetime.now(UTC), content={"raw": "alert"}
    )
    help_request = store.create_help_request(
        "a", task.task_id, "forensics", "Need source logs"
    )
    action = store.create_action_attempt("a", task.task_id, "isolate", ["host-1"])
    reopened = OrchestrationStore(Database(store.db.db_path))
    assert reopened.get_task("a", task.task_id) == task
    assert reopened.get_agent_run("a", run.run_id) == run
    assert reopened.get_evidence("a", evidence.evidence_id) == evidence
    assert reopened.get_help_request("a", help_request.help_request_id) == help_request
    assert reopened.get_action_attempt("a", action.attempt_id) == action
    assert len(reopened.list_action_events("a", action.attempt_id)) == 1
    assert reopened.db.fetchone(
        "SELECT name FROM organizations WHERE org_id=?", ("a",)
    ) == {"name": "a"}
    for identifier in (
        task.task_id,
        run.run_id,
        evidence.evidence_id,
        help_request.help_request_id,
        action.attempt_id,
    ):
        UUID(identifier)
    assert task.status == "queued"
    assert run.status == "queued"
    assert action.status == "proposed"


def test_additive_initialization_preserves_legacy_data(tmp_path: Path):
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE organizations(org_id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT INTO organizations VALUES('legacy','Legacy tenant','2025-01-01')"
    )
    connection.execute("CREATE TABLE untouched_data(secret TEXT, note TEXT)")
    connection.execute("INSERT INTO untouched_data VALUES('original','preserve me')")
    connection.commit()
    connection.close()
    original_global = Database._instance
    db = Database(str(path))
    Database(str(path))
    assert Database._instance is original_global
    assert db.fetchone("SELECT * FROM untouched_data") == {
        "secret": "original",
        "note": "preserve me",
    }
    assert make_task(OrchestrationStore(db), org="legacy").status == "queued"


def test_parent_must_share_tenant_and_incident(store: OrchestrationStore):
    parent = make_task(store)
    child = make_task(store, parent_task_id=parent.task_id)
    assert child.parent_task_id == parent.task_id
    for org, incident in (("b", "incident-1"), ("a", "incident-other")):
        with pytest.raises(
            OrchestrationNotFoundError, match="Orchestration record not found"
        ):
            make_task(store, org, incident, parent_task_id=parent.task_id)
    with pytest.raises(OrchestrationNotFoundError):
        make_task(store, "missing-tenant")
    assert len(store.list_tasks("a")) == 2


def test_all_task_children_are_tenant_scoped(store: OrchestrationStore):
    task = make_task(store)
    records = (
        (
            store.create_agent_run("a", task.task_id),
            store.get_agent_run,
            store.list_agent_runs,
            "run_id",
        ),
        (
            store.create_evidence(
                "a", task.task_id, "siem", datetime.now(UTC), content_ref="logs/1"
            ),
            store.get_evidence,
            store.list_evidence,
            "evidence_id",
        ),
        (
            store.create_help_request("a", task.task_id, "specialist", "Review this"),
            store.get_help_request,
            store.list_help_requests,
            "help_request_id",
        ),
        (
            store.create_action_attempt("a", task.task_id, "isolate", ["host"]),
            store.get_action_attempt,
            store.list_action_attempts,
            "attempt_id",
        ),
    )
    for record, get, list_records, key in records:
        with pytest.raises(OrchestrationNotFoundError) as cross:
            get("b", getattr(record, key))
        with pytest.raises(OrchestrationNotFoundError) as missing:
            get("b", "missing")
        assert str(cross.value) == str(missing.value)
        assert list_records("b", task_id=task.task_id) == []
        assert list_records("a", task_id=task.task_id) == [record]
    factories = (
        lambda: store.create_agent_run("b", task.task_id),
        lambda: store.create_evidence(
            "b", task.task_id, "siem", datetime.now(UTC), content="raw"
        ),
        lambda: store.create_help_request("b", task.task_id, "specialist", "Review"),
        lambda: store.create_action_attempt("b", task.task_id, "isolate", ["host"]),
    )
    for factory in factories:
        with pytest.raises(OrchestrationNotFoundError):
            factory()
    with pytest.raises(OrchestrationNotFoundError):
        store.transition_task("b", task.task_id, "queued", "running")
    assert store.list_tasks("b") == []


def test_composite_database_foreign_keys_reject_cross_scope(store: OrchestrationStore):
    task = make_task(store)
    with pytest.raises(sqlite3.IntegrityError):
        store.db.execute(
            "INSERT INTO orchestration_agent_runs(org_id,run_id,incident_id,task_id,status,created_at,payload_json) VALUES(?,?,?,?,?,?,?)",
            ("b", "run", task.incident_id, task.task_id, "queued", "now", "{}"),
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.db.execute(
            "INSERT INTO orchestration_tasks(org_id,task_id,incident_id,parent_task_id,status,request_hash,created_at,payload_json) VALUES(?,?,?,?,?,?,?,?)",
            (
                "a",
                "child",
                "other-incident",
                task.task_id,
                "queued",
                "hash",
                "now",
                "{}",
            ),
        )


def test_idempotency_is_payload_and_tenant_scoped(store: OrchestrationStore):
    first = make_task(store, idempotency_key="request-1")
    running = store.transition_task("a", first.task_id, "queued", "running")
    assert make_task(store, idempotency_key="request-1") == running
    assert (
        make_task(store, org="b", idempotency_key="request-1").task_id != first.task_id
    )
    for kwargs in ({"priority": 1}, {"parent_task_id": first.task_id}):
        with pytest.raises(OrchestrationConflictError):
            make_task(store, idempotency_key="request-1", **kwargs)
    with pytest.raises(OrchestrationConflictError):
        make_task(store, incident="different", idempotency_key="request-1")
    assert len(store.list_tasks("a")) == 1


def test_task_transitions_are_compare_and_swap(store: OrchestrationStore):
    task = make_task(store)
    with pytest.raises(OrchestrationTransitionError):
        store.transition_task("a", task.task_id, "queued", "completed")
    running = store.transition_task("a", task.task_id, "queued", "running")
    assert running.started_at is not None
    with pytest.raises(OrchestrationConflictError):
        store.transition_task("a", task.task_id, "queued", "running")
    store.transition_task("a", task.task_id, "running", "waiting")
    resumed = store.transition_task("a", task.task_id, "waiting", "running")
    assert resumed.started_at == running.started_at
    completed = store.transition_task("a", task.task_id, "running", "completed")
    assert completed.completed_at is not None
    with pytest.raises(OrchestrationTransitionError):
        store.transition_task("a", task.task_id, "completed", "running")


def test_runs_and_help_have_legal_transitions(store: OrchestrationStore):
    task = make_task(store)
    run = store.create_agent_run("a", task.task_id)
    with pytest.raises(OrchestrationTransitionError):
        store.transition_agent_run("a", run.run_id, "queued", "completed")
    store.transition_agent_run("a", run.run_id, "queued", "running")
    with pytest.raises(OrchestrationTransitionError):
        store.transition_agent_run("a", run.run_id, "running", "failed")
    failed = store.transition_agent_run(
        "a", run.run_id, "running", "failed", error="Provider unavailable"
    )
    assert failed.error == "Provider unavailable"
    assert failed.completed_at is not None
    request = store.create_help_request(
        "a", task.task_id, "responder", "Need assistance"
    )
    store.transition_help_request("a", request.help_request_id, "open", "assigned")
    resolved = store.transition_help_request(
        "a", request.help_request_id, "assigned", "resolved"
    )
    assert resolved.completed_at is not None


def test_evidence_is_immutable_with_content_hash(store: OrchestrationStore):
    task = make_task(store)
    one = store.create_evidence(
        "a", task.task_id, "siem", datetime.now(UTC), content={"a": 1, "b": 2}
    )
    two = store.create_evidence(
        "a", task.task_id, "siem", datetime.now(UTC), content={"b": 2, "a": 1}
    )
    assert one.content_hash == two.content_hash
    with pytest.raises(ValidationError):
        one.source = "changed"
    for query in (
        "UPDATE orchestration_evidence SET payload_json='{}' WHERE evidence_id=?",
        "DELETE FROM orchestration_evidence WHERE evidence_id=?",
    ):
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store.db.execute(query, (one.evidence_id,))
    assert store.get_evidence("a", one.evidence_id) == one
    with pytest.raises(ValidationError):
        store.create_evidence("a", task.task_id, "siem", datetime.now(UTC))


def test_action_attempt_audit_requires_outcome_and_rolls_back(
    store: OrchestrationStore, monkeypatch
):
    task = make_task(store)
    attempt = store.create_action_attempt("a", task.task_id, "isolate", ["host"])
    with pytest.raises(OrchestrationTransitionError):
        store.transition_action_attempt(
            "a",
            attempt.attempt_id,
            "proposed",
            "verified",
            actor="operator",
            outputs={"ok": True},
        )
    store.transition_action_attempt(
        "a", attempt.attempt_id, "proposed", "approved", actor="operator"
    )
    store.transition_action_attempt(
        "a", attempt.attempt_id, "approved", "dispatched", actor="operator"
    )
    store.transition_action_attempt(
        "a",
        attempt.attempt_id,
        "dispatched",
        "acknowledged",
        actor="operator",
        outputs={"ack": "id"},
    )
    with pytest.raises(OrchestrationTransitionError):
        store.transition_action_attempt(
            "a", attempt.attempt_id, "acknowledged", "verified", actor="operator"
        )
    original_insert = store._insert

    def fail_insert(*args, **kwargs):
        raise sqlite3.OperationalError("Injected audit failure")

    monkeypatch.setattr(store, "_insert", fail_insert)
    with pytest.raises(sqlite3.OperationalError, match="Injected audit failure"):
        store.transition_action_attempt(
            "a",
            attempt.attempt_id,
            "acknowledged",
            "verified",
            actor="operator",
            outputs={"observation": "Host disconnected"},
        )
    assert store.get_action_attempt("a", attempt.attempt_id).status == "acknowledged"
    monkeypatch.setattr(store, "_insert", original_insert)
    verified = store.transition_action_attempt(
        "a",
        attempt.attempt_id,
        "acknowledged",
        "verified",
        actor="operator",
        outputs={"observation": "Host disconnected"},
    )
    assert verified.status == "verified"
    events = store.list_action_events("a", attempt.attempt_id)
    assert [event.status for event in events] == [
        "proposed",
        "approved",
        "dispatched",
        "acknowledged",
        "verified",
    ]
    assert events[-1].outputs == {"observation": "Host disconnected"}
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        store.db.execute(
            "DELETE FROM orchestration_action_events WHERE event_id=?",
            (events[0].event_id,),
        )
    with pytest.raises(OrchestrationNotFoundError):
        store.list_action_events("b", attempt.attempt_id)


def test_strict_models_utc_and_bounds(store: OrchestrationStore):
    task = make_task(store)
    values = task.model_dump()
    for changes in (
        {"priority": "1"},
        {"priority": True},
        {"priority": -1},
        {"unexpected": "field"},
        {"objective": " "},
        {"role": "r" * 121},
        {"status": "fake"},
        {"created_at": datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)},
    ):
        with pytest.raises(ValidationError):
            Task.model_validate(values | changes)
    local = datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=3)))
    normalized = Task.model_validate(values | {"created_at": local})
    assert normalized.created_at == local.astimezone(UTC)
    assert normalized.created_at.tzinfo == UTC
    with pytest.raises(ValueError, match="256 KiB"):
        store.create_evidence(
            "a", task.task_id, "siem", datetime.now(UTC), content="x" * 262144
        )
    for kwargs in ({"limit": 201}, {"limit": True}, {"offset": -1}):
        with pytest.raises(ValueError):
            store.list_tasks("a", **kwargs)


def test_parameterized_filters_and_stable_paging(store: OrchestrationStore):
    first = make_task(store, incident="incident' OR 1=1 --")
    second = make_task(store)
    assert store.list_tasks("a", incident_id=first.incident_id) == [first]
    ordered = sorted([first, second], key=lambda task: (task.created_at, task.task_id))
    assert store.list_tasks("a", limit=1, offset=1) == ordered[1:]
    assert store.list_tasks("a' OR 1=1 --") == []


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_json_is_rejected_without_data_loss(
    store: OrchestrationStore, number
):
    task = make_task(store)
    with pytest.raises(ValidationError):
        store.create_action_attempt(
            "a",
            task.task_id,
            "isolate",
            ["host"],
            inputs={"nested": [{"score": number}]},
        )
    assert store.list_action_attempts("a") == []
    run = store.create_agent_run("a", task.task_id)
    store.transition_agent_run("a", run.run_id, "queued", "running")
    with pytest.raises(ValidationError):
        store.transition_agent_run(
            "a", run.run_id, "running", "completed", result={"nested": [number]}
        )
    assert store.get_agent_run("a", run.run_id).status == "running"
    attempt = store.create_action_attempt("a", task.task_id, "isolate", ["host"])
    with pytest.raises(ValidationError):
        store.transition_action_attempt(
            "a",
            attempt.attempt_id,
            "proposed",
            "approved",
            actor="operator",
            outputs={"nested": [number]},
        )
    assert store.get_action_attempt("a", attempt.attempt_id).status == "proposed"
    assert len(store.list_action_events("a", attempt.attempt_id)) == 1


def test_interrupted_multiwrite_rolls_back(store: OrchestrationStore, monkeypatch):
    task = make_task(store)
    original_insert = store._insert

    def interrupt_audit(record, **kwargs):
        from terminus.orchestration.models import ActionAttemptEvent

        if isinstance(record, ActionAttemptEvent):
            raise KeyboardInterrupt
        original_insert(record, **kwargs)

    monkeypatch.setattr(store, "_insert", interrupt_audit)
    with pytest.raises(KeyboardInterrupt):
        store.create_action_attempt("a", task.task_id, "isolate", ["host"])
    assert store.list_action_attempts("a") == []
    monkeypatch.setattr(store, "_insert", original_insert)
    assert (
        store.create_action_attempt("a", task.task_id, "isolate", ["host"]).status
        == "proposed"
    )
