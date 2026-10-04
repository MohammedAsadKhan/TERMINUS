"""Observed evidence is bounded, durable and fenced by scheduler ownership."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from terminus.orchestration.scheduler_store import SchedulerLeaseError, SchedulerStore
from terminus.storage.db import Database
from terminus.toolkit.audit import ToolAuditError, ToolInvocationStore
from terminus.toolkit.evidence import ToolEvidenceWriter, query_digest
from terminus.toolkit.models import (
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
    ToolLimits,
)
from terminus.toolkit.validation import ToolContractDeniedError, ToolContractValidator

NOW = datetime(2026, 10, 4, 6, tzinfo=UTC)


@pytest.fixture
def collector(tmp_path):
    db = Database(str(tmp_path / "evidence.db"))
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("a", "Fixture", NOW.isoformat()),
    )
    db.execute(
        "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (
            "incident",
            "a",
            "alert",
            "high",
            "high",
            "Fixture",
            "[]",
            "standard",
            NOW.isoformat(),
        ),
    )
    scheduler = SchedulerStore(db, clock=lambda: NOW)
    task = scheduler.records.create_incident_task(
        "a", "incident", "alert_handling", "triage", "Observe fixture"
    )
    scheduler.enqueue_task("a", task.task_id)
    scheduler.acquire_coordinator("owner")
    lease = scheduler.claim_next("owner", "worker", ["triage"])
    assert lease is not None
    context = ToolExecutionContext(
        org_id="a",
        incident_id="incident",
        task_id=task.task_id,
        run_id=lease.run_id,
        role="triage",
        granted_tool_ids=("fixture.read",),
        permitted_resource_ids=("host",),
        permitted_connector_ids=("fixture",),
        policy_version="p1",
        budget_reservation_id="fixture-budget",
        invocation_count=0,
        lease=lease,
    )
    descriptor = ToolDescriptor(
        tool_id="fixture.read",
        version="1.0",
        name="Fixture read",
        family="incident_alerts",
        availability="available",
        release="1.0",
        permitted_roles=("triage",),
        connector_ids=("fixture",),
        input_contract="read_query",
        output_contract="tool_result",
        effect="read",
        resource_scope="incident",
        egress="none",
        requires_approval=False,
        idempotency_required=False,
        limits=ToolLimits(),
        acceptance_checks=("Fixture",),
        expected_evidence=("Observed event",),
    )
    query = ReadQuery(resource_id="host", start=NOW - timedelta(minutes=30), end=NOW)
    audit = ToolInvocationStore(db, clock=lambda: NOW)
    reservation = audit.reserve(descriptor, context, query)
    context = context.model_copy(update={"invocation_id": reservation.invocation_id})
    writer = ToolEvidenceWriter(ToolContractValidator(scheduler), audit)
    yield writer, descriptor, context, query
    db.close()


def record(collector, **updates):
    writer, descriptor, context, query = collector
    arguments = {
        "connector_id": "fixture",
        "connector_version": "1",
        "source_id": "authlog",
        "source_timestamp": NOW - timedelta(minutes=5),
        "content": {"event": "failed_login"},
        "source_event_ids": ("event-1",),
    }
    return writer.record(descriptor, context, query, **(arguments | updates))


def test_evidence_survives_restart_with_source_and_scope(collector):
    writer, descriptor, context, query = collector
    ref, provenance = record(collector)
    path = writer.validator.scheduler.db.db_path
    writer.validator.scheduler.db.close()
    reopened = Database(path)
    try:
        records = SchedulerStore(reopened, clock=lambda: NOW).records
        observed = records.get_evidence("a", ref.evidence_id)
        assert observed.content_hash == ref.content_hash
        assert observed.incident_id == context.incident_id
        assert observed.content["run_id"] == context.run_id
        assert observed.content["tool_id"] == descriptor.tool_id
        assert observed.content["provenance"] == provenance.model_dump(mode="json")
        assert provenance.query_digest == query_digest(query)
        assert observed.content["observed"] == {"event": "failed_login"}
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "updates",
    [
        {"content": None},
        {"content": "x" * 65536},
        {"connector_id": "other"},
        {"source_timestamp": NOW + timedelta(seconds=1)},
        {"source_timestamp": NOW - timedelta(hours=2)},
        {"source_event_ids": tuple(f"event-{n}" for n in range(801))},
    ],
)
def test_missing_or_unbounded_observations_write_nothing(collector, updates):
    writer, _, _, _ = collector
    with pytest.raises(ToolContractDeniedError):
        record(collector, **updates)
    assert writer.validator.records.list_evidence("a") == []


def test_nonfinite_observation_writes_nothing(collector):
    writer, _, _, _ = collector
    with pytest.raises(ValueError):
        record(collector, content={"value": float("nan")})
    assert writer.validator.records.list_evidence("a") == []


def test_stale_collector_cannot_write(collector):
    writer, descriptor, context, query = collector
    stale = context.model_copy(
        update={"lease": context.lease.model_copy(update={"lease_token": "stale"})}
    )
    with pytest.raises(SchedulerLeaseError):
        record((writer, descriptor, stale, query))
    assert writer.validator.records.list_evidence("a") == []


def test_cancelled_collector_cannot_write(collector):
    writer, _, context, _ = collector
    writer.validator.scheduler.request_cancel(context.org_id, context.task_id)
    with pytest.raises(ToolContractDeniedError):
        record(collector)
    assert writer.validator.records.list_evidence("a") == []


def test_hash_covers_provenance_and_observed_content(collector):
    first, _ = record(collector)
    second, _ = record(collector, content={"event": "successful_login"})
    assert first.content_hash != second.content_hash
    assert json.loads(json.dumps(first.model_dump()))["incident_id"] == "incident"


def test_finished_invocation_cannot_publish_late_evidence(collector):
    writer, _, context, _ = collector
    reservation = writer.audit.list_pending(context.org_id, context.task_id)[0]
    writer.audit.finish(reservation, context, uncertain=True)
    with pytest.raises(ToolAuditError):
        record(collector)
    assert writer.validator.records.list_evidence("a") == []


def test_unreserved_evidence_cannot_be_collected(collector):
    writer, descriptor, context, query = collector
    unreserved = context.model_copy(update={"invocation_id": "missing"})
    with pytest.raises(ToolAuditError):
        record((writer, descriptor, unreserved, query))
    with pytest.raises(ToolAuditError, match="does not match"):
        writer.audit.assert_pending(
            context, descriptor.model_copy(update={"connector_ids": ("other",)}), query
        )
    assert writer.validator.records.list_evidence("a") == []
