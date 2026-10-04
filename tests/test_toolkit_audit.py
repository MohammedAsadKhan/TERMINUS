"""Reservation quota, restart and stale completion fencing."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import sqlite3

import pytest

from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database
from terminus.toolkit.audit import ToolAuditError, ToolInvocationStore, ToolQuotaError
from terminus.toolkit.catalog import load_catalog
from terminus.toolkit.models import (
    EvidenceReference,
    ReadQuery,
    ToolExecutionContext,
    ToolResult,
)


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "tools.db"))
    now = [datetime(2026, 10, 4, tzinfo=UTC)]

    def clock():
        return now[0]

    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("org", "Org", now[0].isoformat()),
    )
    db.execute(
        """INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,
        summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            "incident",
            "org",
            "alert",
            "high",
            "high",
            "Fixture",
            "[]",
            "standard",
            now[0].isoformat(),
        ),
    )
    scheduler = SchedulerStore(db, clock=clock)
    task = scheduler.records.create_incident_task(
        "org", "incident", "triage", "triage", "Inspect"
    )
    scheduler.enqueue_task("org", task.task_id)
    scheduler.acquire_coordinator("coordinator", lease_seconds=300)
    lease = scheduler.claim_next("coordinator", "worker", {"triage"}, lease_seconds=60)
    descriptor = next(
        tool
        for tool in load_catalog().tools
        if tool.effect == "read" and "triage" in tool.permitted_roles
    )
    descriptor = descriptor.model_copy(update={"availability": "available"})
    context = ToolExecutionContext(
        org_id="org",
        incident_id="incident",
        task_id=task.task_id,
        run_id=lease.run_id,
        role="triage",
        granted_tool_ids=(descriptor.tool_id,),
        permitted_resource_ids=("fixture",),
        permitted_connector_ids=descriptor.connector_ids,
        policy_version="v1",
        budget_reservation_id="budget",
        invocation_count=0,
        egress_authorized=True,
        lease=lease,
    )
    query = ReadQuery(
        resource_id="fixture", start=now[0] - timedelta(minutes=5), end=now[0]
    )
    audit = ToolInvocationStore(db, clock=clock)
    yield audit, scheduler, context, descriptor, query, now
    db.close()


def test_reserves_before_completion_and_restart_counts_pending(setup):
    audit, _, context, descriptor, query, _ = setup
    reservations = [audit.reserve(descriptor, context, query) for _ in range(20)]
    assert len(audit.list_pending("org", context.task_id)) == 20
    audit.db.close()
    restarted = ToolInvocationStore(Database(audit.db.db_path), clock=audit.clock)
    with pytest.raises(ToolQuotaError):
        restarted.reserve(descriptor, context, query)
    result = ToolResult(
        tool_id=descriptor.tool_id, version="1.0", status="empty", coverage="complete"
    )
    invocation = restarted.finish(reservations[0], context, result)
    assert invocation.outcome == "empty"
    assert restarted.count("org", context.task_id) == 20
    assert restarted.finish(reservations[0], context, uncertain=True) == invocation
    assert restarted.list_invocations("foreign", context.task_id) == []
    restarted.db.close()


def test_quota_is_atomic_across_connections(setup):
    audit, _, context, descriptor, query, _ = setup
    for _ in range(18):
        audit.reserve(descriptor, context, query)

    def attempt(_):
        store = ToolInvocationStore(Database(audit.db.db_path), clock=audit.clock)
        try:
            return store.reserve(descriptor, context, query).invocation_id
        except ToolQuotaError:
            return None
        finally:
            store.db.close()

    with ThreadPoolExecutor(max_workers=6) as workers:
        results = list(workers.map(attempt, range(12)))
    assert sum(result is not None for result in results) == 2
    assert audit.count("org", context.task_id) == 20


@pytest.mark.parametrize(
    "cause",
    [
        "cancellation",
        "worker_expired",
        "coordinator_expired",
        "canonical_role",
        "run_completed",
    ],
)
def test_ownership_checked_atomically_before_and_after_io(setup, cause):
    audit, scheduler, context, descriptor, query, now = setup
    reservation = audit.reserve(descriptor, context, query)
    if cause == "cancellation":
        scheduler.request_cancel("org", context.task_id)
    elif cause == "worker_expired":
        now[0] += timedelta(seconds=60)
    elif cause == "coordinator_expired":
        audit.db.execute(
            "UPDATE orchestration_scheduler_coordinator SET lease_expires_at=?",
            (now[0].isoformat(),),
        )
    elif cause == "canonical_role":
        task = scheduler.records.get_task("org", context.task_id)
        audit.db.execute(
            "UPDATE orchestration_tasks SET payload_json=? WHERE org_id=? AND task_id=?",
            (
                task.model_copy(update={"role": "network"}).model_dump_json(),
                "org",
                context.task_id,
            ),
        )
    else:
        scheduler.records.transition_agent_run(
            "org", context.run_id, "running", "completed", result={}
        )
    with pytest.raises(ToolAuditError):
        audit.reserve(descriptor, context, query)
    invocation = audit.finish(
        reservation,
        context,
        ToolResult(tool_id=descriptor.tool_id, version="1.0", status="ok"),
    )
    assert invocation.outcome == "unknown"
    assert invocation.evidence_ids == ()


def test_uncertain_finish_keeps_quota_and_no_bearer_secrets_or_raw_args(setup):
    audit, _, context, descriptor, query, _ = setup
    reservation = audit.reserve(descriptor, context, query)
    assert audit.finish(reservation, context, uncertain=True).outcome == "unknown"
    row = audit.db.fetchone("SELECT payload_json FROM toolkit_invocation_reservations")
    assert query.resource_id not in row["payload_json"]
    assert context.lease.lease_token not in row["payload_json"]
    assert context.lease.coordinator_token not in row["payload_json"]
    assert audit.count("org", context.task_id) == 1


def test_caller_count_is_never_quota_authority_and_denials_are_audited(setup):
    audit, _, context, descriptor, query, _ = setup
    context = context.model_copy(update={"invocation_count": 20})
    assert audit.reserve(descriptor, context, query)
    invocation = audit.record_denial(
        context, descriptor.tool_id, "f" * 64, "invalid_arguments"
    )
    assert invocation.policy_decision == "denied"
    assert audit.count("org", context.task_id) == 1
    assert invocation in audit.list_invocations("org", context.task_id)
    for table in ("toolkit_invocation_reservations", "toolkit_invocation_denials"):
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            audit.db.execute(f"DELETE FROM {table}")  # noqa: S608 - known test tables


def test_forged_reservation_and_evidence_hash_cannot_finalize(setup):
    audit, scheduler, context, descriptor, query, now = setup
    reservation = audit.reserve(descriptor, context, query)
    with pytest.raises(ToolAuditError):
        audit.finish(
            reservation.model_copy(update={"arguments_digest": "e" * 64}),
            context,
            uncertain=True,
        )
    evidence = scheduler.records.create_evidence(
        "org", context.task_id, "fixture", now[0], content={"event": "one"}
    )
    result = ToolResult(
        tool_id=descriptor.tool_id,
        version="1.0",
        status="ok",
        evidence=(
            EvidenceReference(
                evidence_id=evidence.evidence_id,
                org_id="org",
                incident_id="incident",
                content_hash="a" * 64,
            ),
        ),
    )
    with pytest.raises(ToolAuditError, match="hash"):
        audit.finish(reservation, context, result)
    assert audit.list_pending("org", context.task_id) == [reservation]
    assert audit.finish(reservation, context, uncertain=True).outcome == "unknown"


def test_future_and_dispatch_denied_before_reservation(setup):
    audit, _, context, descriptor, query, _ = setup
    for rejected in (
        descriptor.model_copy(update={"release": "future"}),
        descriptor.model_copy(update={"effect": "proposal"}),
    ):
        with pytest.raises(ToolAuditError):
            audit.reserve(rejected, context, query)
    assert audit.count("org", context.task_id) == 0


def test_pending_evidence_write_fence_rejects_late_and_unbound_handlers(setup):
    audit, _, context, descriptor, query, _ = setup
    reservation = audit.reserve(descriptor, context, query)
    with pytest.raises(ToolAuditError, match="No pending"):
        audit.assert_pending(context, descriptor, query)
    bound = context.model_copy(
        update={"invocation_id": reservation.invocation_id}
    )
    assert audit.assert_pending(bound, descriptor, query) == reservation
    with pytest.raises(ToolAuditError):
        audit.assert_pending(
            bound, descriptor, query.model_copy(update={"page_size": 1})
        )
    audit.finish(reservation, bound, uncertain=True)
    with pytest.raises(ToolAuditError, match="completed"):
        audit.assert_pending(bound, descriptor, query)


def test_pending_deadline_fences_late_evidence_and_completion(setup):
    audit, _, context, descriptor, query, now = setup
    reservation = audit.reserve(descriptor, context, query)
    bound = context.model_copy(
        update={"invocation_id": reservation.invocation_id}
    )
    now[0] += timedelta(seconds=descriptor.limits.timeout_seconds)
    with pytest.raises(ToolAuditError, match="deadline"):
        audit.assert_pending(bound, descriptor, query)
    assert (
        audit.finish(
            reservation,
            bound,
            ToolResult(tool_id=descriptor.tool_id, version="1.0", status="ok"),
        ).outcome
        == "unknown"
    )


def test_denial_cap_survives_restart_and_is_atomic(setup):
    audit, _, context, descriptor, _, _ = setup
    for _ in range(18):
        audit.record_denial(context, descriptor.tool_id, "f" * 64, "denied")

    def attempt(_):
        store = ToolInvocationStore(Database(audit.db.db_path), clock=audit.clock)
        try:
            store.record_denial(context, descriptor.tool_id, "f" * 64, "denied")
            return True
        except ToolAuditError as exc:
            assert exc.code == "denial_quota_exhausted"  # noqa: PT017 - worker returns quota outcome
            return False
        finally:
            store.db.close()

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert sum(workers.map(attempt, range(8))) == 2
    assert len(audit.list_invocations("org", context.task_id)) == 20
    assert audit.count("org", context.task_id) == 0
