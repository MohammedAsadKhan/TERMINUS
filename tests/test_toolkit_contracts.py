"""Contract fixtures prove safety boundaries without invoking a security tool."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from terminus.orchestration.scheduler_store import SchedulerLeaseError, SchedulerStore
from terminus.orchestration.storage import OrchestrationNotFoundError
from terminus.storage.db import Database
from terminus.toolkit.catalog import CORE_ROLES, ToolkitCatalog, load_catalog
from terminus.toolkit.models import (
    ApprovalBinding,
    EvidenceReference,
    Provenance,
    ReadQuery,
    ResponseProposal,
    ScopedEffect,
    ToolDescriptor,
    ToolExecutionContext,
    ToolInvocation,
    ToolLimits,
    ToolResult,
    VerificationObservation,
    VerificationReport,
)
from terminus.toolkit.validation import (
    ToolContractDeniedError,
    ToolContractValidator,
    validate_approval,
)

NOW = datetime(2026, 10, 4, 6, 0, tzinfo=UTC)


@pytest.fixture
def leased(tmp_path):
    db = Database(str(tmp_path / "contracts.db"))
    for org in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, NOW.isoformat()),
        )
        for suffix in ("1", "2"):
            db.execute(
                "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    f"incident-{org}-{suffix}",
                    org,
                    f"alert-{suffix}",
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
        "a", "incident-a-1", "alert_handling", "triage", "Inspect fixture"
    )
    scheduler.enqueue_task("a", task.task_id)
    scheduler.acquire_coordinator("owner")
    lease = scheduler.claim_next("owner", "worker", ["triage"])
    assert lease is not None
    context = ToolExecutionContext(
        org_id="a",
        incident_id=task.incident_id,
        task_id=task.task_id,
        run_id=lease.run_id,
        role="triage",
        granted_tool_ids=("fixture.read",),
        permitted_resource_ids=("host-1",),
        permitted_connector_ids=("fixture-source",),
        policy_version="policy-v1",
        budget_reservation_id="fixture-budget",
        invocation_count=0,
        lease=lease,
    )
    yield scheduler, context
    db.close()


def descriptor(**updates):
    """Synthetic available fixture; not part of the dormant shipped catalog."""
    data = {
        "tool_id": "fixture.read",
        "version": "1.0",
        "name": "Fixture reader",
        "family": "incident_alerts",
        "availability": "available",
        "release": "1.0",
        "permitted_roles": ("triage",),
        "connector_ids": ("fixture-source",),
        "input_contract": "read_query",
        "output_contract": "tool_result",
        "effect": "read",
        "resource_scope": "incident",
        "egress": "none",
        "requires_approval": False,
        "idempotency_required": False,
        "limits": ToolLimits(),
        "acceptance_checks": ("Recorded fixture only",),
        "expected_evidence": ("Source event",),
    }
    return ToolDescriptor(**(data | updates))


def query(**updates):
    return ReadQuery(
        **(
            {"resource_id": "host-1", "start": NOW - timedelta(minutes=30), "end": NOW}
            | updates
        )
    )


def test_complete_catalog_matches_roadmap_and_has_no_execution():
    catalog = load_catalog()
    roadmap = (
        Path("docs/FUTURE_SCOPE.md")
        .read_text(encoding="utf-8")
        .split("## Full roadmap catalog")[1]
        .split("## Explicit capability additions")[0]
    )
    names = {line[2:] for line in roadmap.splitlines() if line.startswith("- ")}
    assert {item.name for item in catalog.specialties} == names
    assert len(names) == 60
    assert {item.role for item in catalog.core_bundles} == CORE_ROLES
    assert not any(
        item.availability == "available"
        for item in (*catalog.tools, *catalog.connectors)
    )


def test_recorded_contract_fixtures_keep_missing_data_distinct_from_empty():
    fixture = json.loads(
        Path("tests/fixtures/toolkit/outcomes.json").read_text(encoding="utf-8")
    )
    assert fixture["fixture_kind"] == "synthetic_contract_fixture_not_live_telemetry"
    results = [
        ToolResult.model_validate_json(json.dumps(row)) for row in fixture["results"]
    ]
    assert {item.status for item in results} == {
        "unavailable",
        "unsupported",
        "empty",
        "partial",
    }
    assert all(item.data is None for item in results)


def test_exported_schemas_match_the_strict_models():
    from terminus.toolkit import models

    catalog = load_catalog()
    exported = json.loads(
        Path("src/terminus/toolkit/contracts.schema.json").read_text(encoding="utf-8")
    )
    for name, schema in exported.items():
        model = ToolkitCatalog if name == "ToolkitCatalog" else getattr(models, name)
        assert schema == json.loads(json.dumps(model.model_json_schema()))
    assert all(
        item.core_role is not None or item.availability == "planned"
        for item in catalog.specialties
    )
    assert {item.family for item in catalog.tools} == set(
        ToolDescriptor.model_json_schema()["properties"]["family"]["enum"]
    )
    assert not any(
        tool.effect == "dispatch"
        for bundle in catalog.core_bundles
        for tool in catalog.tools
        if tool.tool_id in bundle.tool_ids
    )


def test_catalog_rejects_unknown_references_and_future_core_grants():
    data = load_catalog().model_dump(mode="json")
    data["core_bundles"][0]["tool_ids"].append("unknown.tool")
    with pytest.raises(ValidationError, match="unknown tools"):
        ToolkitCatalog.model_validate_json(json.dumps(data))
    data = load_catalog().model_dump(mode="json")
    future = next(tool for tool in data["tools"] if tool["release"] == "future")
    future["permitted_roles"].append("triage")
    with pytest.raises(ValidationError, match="future tools"):
        ToolkitCatalog.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "changes",
    [
        {"command": "whoami"},
        {"org_id": "b"},
        {"resource_id": "https://example.test"},
        {"resource_id": "../../file"},
        {"sql": "SELECT *"},
        {"page_size": 201},
        {"max_pages": 5},
        {"start": NOW - timedelta(hours=2)},
        {"end": NOW.replace(tzinfo=None)},
    ],
)
def test_queries_reject_scope_injection_and_unbounded_input(changes):
    with pytest.raises(ValidationError):
        query(**changes)


def test_role_resource_egress_budget_and_stale_owner_are_denied(leased):
    scheduler, context = leased
    gate = ToolContractValidator(scheduler)
    gate.validate_request(descriptor(), context, query())
    for denied_context in (
        context.model_copy(update={"granted_tool_ids": ()}),
        context.model_copy(update={"permitted_resource_ids": ()}),
        context.model_copy(update={"cancelled": True}),
        context.model_copy(update={"invocation_count": 20}),
    ):
        with pytest.raises(ToolContractDeniedError):
            gate.validate_request(descriptor(), denied_context, query())
    for denied_tool in (
        descriptor(availability="implementation_pending"),
        descriptor(release="future"),
        descriptor(tool_id="unknown.tool"),
        descriptor(permitted_roles=("identity",)),
        descriptor(connector_ids=("foreign-connector",)),
        descriptor(egress="policy_required"),
    ):
        with pytest.raises(ToolContractDeniedError):
            gate.validate_request(denied_tool, context, query())
    scheduler.clock = lambda: NOW + timedelta(seconds=60)
    with pytest.raises(SchedulerLeaseError):
        gate.validate_request(descriptor(), context, query())


def test_context_cannot_claim_foreign_tenant_or_future_role(leased):
    _, context = leased
    data = context.model_dump(mode="json")
    for changes in (
        {"org_id": "b"},
        {"incident_id": "incident-a-2"},
        {"role": "cloud_security_analyst"},
    ):
        with pytest.raises(ValidationError):
            ToolExecutionContext.model_validate_json(json.dumps(data | changes))


def test_copied_context_cannot_bypass_scope_or_cancel_checks(leased):
    scheduler, context = leased
    gate = ToolContractValidator(scheduler)
    with pytest.raises(ValidationError):
        gate.validate_request(
            descriptor(), context.model_copy(update={"org_id": "b"}), query()
        )
    scheduler.request_cancel(context.org_id, context.task_id)
    with pytest.raises(ToolContractDeniedError, match="Cancellation"):
        gate.validate_request(descriptor(), context, query())


def test_result_requires_scoped_persisted_evidence_and_preserves_after_restart(leased):
    scheduler, context = leased
    gate = ToolContractValidator(scheduler)
    evidence = scheduler.records.create_evidence(
        "a",
        context.task_id,
        "fixture",
        NOW,
        content={"fixture": True, "event": "ssh_failure"},
    )
    ref = EvidenceReference(
        evidence_id=evidence.evidence_id,
        content_hash=evidence.content_hash,
        org_id="a",
        incident_id=context.incident_id,
    )
    result = ToolResult(
        tool_id="fixture.read",
        version="1.0",
        status="ok",
        data={"event": "ssh_failure"},
        evidence=(ref,),
        provenance=(
            Provenance(
                source_id="fixture",
                connector_id="fixture-source",
                connector_version="1.0",
                source_event_ids=("evt-1",),
                source_timestamp=NOW,
                collected_at=NOW,
                query_digest="0" * 64,
            ),
        ),
    )
    gate.validate_result(descriptor(), context, result)
    with pytest.raises(ValidationError):
        gate.validate_result(
            descriptor(
                limits=ToolLimits().model_copy(update={"max_output_bytes": 999999})
            ),
            context,
            result,
        )
    with pytest.raises(ToolContractDeniedError, match="connector"):
        gate.validate_result(
            descriptor(connector_ids=("other-source",)), context, result
        )
    reopened = ToolContractValidator(
        SchedulerStore(Database(scheduler.db.db_path), clock=lambda: NOW)
    )
    reopened.validate_result(descriptor(), context, result)
    reopened.scheduler.db.close()
    peer = scheduler.records.create_incident_task(
        "a", context.incident_id, "investigation", "identity", "Peer investigation"
    )
    shared = scheduler.records.create_evidence(
        "a", peer.task_id, "fixture", NOW, content={"event": "peer"}
    )
    # Specialists intentionally share immutable evidence within one incident.
    peer_ref = EvidenceReference(
        evidence_id=shared.evidence_id,
        org_id="a",
        incident_id=context.incident_id,
        content_hash=shared.content_hash,
    )
    gate.validate_result(
        descriptor(), context, result.model_copy(update={"evidence": (peer_ref,)})
    )
    with pytest.raises(ToolContractDeniedError, match="hash"):
        gate.validate_result(
            descriptor(),
            context,
            result.model_copy(
                update={
                    "evidence": (ref.model_copy(update={"content_hash": "0" * 64}),)
                }
            ),
        )
    other = scheduler.records.create_incident_task(
        "a", "incident-a-2", "investigation", "identity", "Other incident"
    )
    foreign = scheduler.records.create_evidence(
        "a", other.task_id, "fixture", NOW, content={"event": "other"}
    )
    for bad in (
        EvidenceReference(
            evidence_id=evidence.evidence_id,
            content_hash=evidence.content_hash,
            org_id="b",
            incident_id=context.incident_id,
        ),
        EvidenceReference(
            evidence_id=foreign.evidence_id,
            content_hash=foreign.content_hash,
            org_id="a",
            incident_id=context.incident_id,
        ),
    ):
        with pytest.raises(ToolContractDeniedError):
            gate.validate_result(
                descriptor(), context, result.model_copy(update={"evidence": (bad,)})
            )
    with pytest.raises(OrchestrationNotFoundError):
        gate.validate_result(
            descriptor(),
            context,
            result.model_copy(
                update={
                    "evidence": (ref.model_copy(update={"evidence_id": "missing"}),)
                }
            ),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"data": "x" * 65536},
        {"data": float("nan")},
        {"status": "unavailable", "data": {"host": "healthy"}},
        {"status": "empty", "coverage": "unknown"},
        {"truncated": True},
    ],
)
def test_result_limits_and_honest_failures(changes):
    with pytest.raises(ValidationError):
        ToolResult(
            **({"tool_id": "fixture.read", "version": "1.0", "status": "ok"} | changes)
        )


def proposal():
    return ResponseProposal(
        proposal_id="proposal-1",
        org_id="a",
        incident_id="incident-a-1",
        task_id="task-1",
        run_id="run-1",
        provider_connection_id="wazuh-response",
        policy_version="policy-v1",
        effect=ScopedEffect(
            action="block_ip",
            target_ids=("host-1",),
            parameter_evidence_id="params-1",
            duration_seconds=60,
            undo_strategy="owned_resource_only",
        ),
        evidence_ids=("evidence-1",),
        prerequisites=("Protected-target checks pass",),
        expected_effect="Attacker connection blocked",
        anticipated_impact="Lab attacker only",
        verification_requirements=("Rule and attacker-path checks",),
        health_requirements=("Management and service healthy",),
        approval_expires_at=NOW + timedelta(minutes=5),
    )


def test_immutable_approval_binding_expiry_and_change_denial():
    plan = proposal()
    approval = ApprovalBinding(
        approval_id="approval-1",
        org_id="a",
        incident_id=plan.incident_id,
        proposal_id=plan.proposal_id,
        proposal_digest=plan.digest(),
        approver_id="human-admin",
        approver_role="admin",
        issued_at=NOW,
        approval_expires_at=plan.approval_expires_at,
    )
    validate_approval(
        plan,
        approval,
        now=NOW,
        requester_id="agent",
        current_policy_version="policy-v1",
    )
    with pytest.raises(ValidationError):
        validate_approval(
            plan,
            approval.model_copy(update={"approver_role": "viewer"}),
            now=NOW,
            requester_id="agent",
            current_policy_version="policy-v1",
        )
    for denied_plan, denied_approval, time, requester, policy in (
        (plan, approval, plan.approval_expires_at, "agent", "policy-v1"),
        (plan, approval, NOW, "human-admin", "policy-v1"),
        (plan, approval, NOW, "agent", "policy-v2"),
        (
            plan.model_copy(
                update={
                    "effect": plan.effect.model_copy(update={"target_ids": ("host-2",)})
                }
            ),
            approval,
            NOW,
            "agent",
            "policy-v1",
        ),
        (plan, approval.model_copy(update={"org_id": "b"}), NOW, "agent", "policy-v1"),
    ):
        with pytest.raises(ToolContractDeniedError):
            validate_approval(
                denied_plan,
                denied_approval,
                now=time,
                requester_id=requester,
                current_policy_version=policy,
            )


def test_unknown_effect_requires_intent_and_never_implies_verification():
    data = {
        "invocation_id": "call-1",
        "org_id": "a",
        "incident_id": "incident-a-1",
        "task_id": "task-1",
        "run_id": "run-1",
        "tool_id": "response.block",
        "tool_version": "1.0",
        "effect": "dispatch",
        "arguments_digest": "0" * 64,
        "policy_version": "policy-v1",
        "policy_decision": "allowed",
        "outcome": "unknown",
        "timestamp": NOW,
    }
    with pytest.raises(ValidationError, match="dispatch identity"):
        ToolInvocation(**data)
    invocation = ToolInvocation(
        **data,
        proposal_digest=proposal().digest(),
        dispatch_intent_id="intent-1",
        idempotency_key="action-1",
    )
    assert (
        ToolInvocation.model_validate_json(invocation.model_dump_json()).outcome
        == "unknown"
    )
    ack = VerificationObservation(
        kind="provider_ack",
        collector_run_id="provider",
        source_id="provider",
        source_timestamp=NOW,
        evidence=EvidenceReference(
            org_id="a",
            incident_id="incident-a-1",
            evidence_id="ack-1",
            content_hash="0" * 64,
        ),
        passed=True,
    )
    report = {
        "org_id": "a",
        "incident_id": "incident-a-1",
        "proposal_digest": proposal().digest(),
        "dispatch_run_id": "run-1",
        "dispatched_at": NOW,
        "status": "verified",
    }
    with pytest.raises(ValidationError, match="independent"):
        VerificationReport(**report, observations=(ack,))
    observations = tuple(
        ack.model_copy(
            update={
                "kind": kind,
                "collector_run_id": "verifier",
                "source_id": kind,
                "evidence": ack.evidence.model_copy(update={"evidence_id": kind}),
            }
        )
        for kind in (
            "endpoint_effect",
            "attacker_path",
            "management_health",
            "service_health",
        )
    )
    assert VerificationReport(**report, observations=observations).status == "verified"
    for invalid in (
        tuple(
            item.model_copy(update={"evidence": ack.evidence}) for item in observations
        ),
        tuple(
            item.model_copy(update={"source_id": "same-source"})
            for item in observations
        ),
        tuple(
            item.model_copy(update={"collector_run_id": "run-1"})
            for item in observations
        ),
        tuple(
            item.model_copy(update={"source_timestamp": NOW - timedelta(seconds=1)})
            for item in observations
        ),
    ):
        with pytest.raises(ValidationError):
            VerificationReport(**report, observations=invalid)
