# pyright: basic, reportPrivateUsage=false, reportAny=false, reportExplicitAny=false
"""Durable response acceptance fixtures; never make live provider calls."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from terminus.orchestration.models import AgentRun, EvidenceRecord
from terminus.orchestration.storage import OrchestrationNotFoundError
from terminus.response.fixtures import FixtureResponseDriver
from terminus.response.models import (
    ParameterBinding,
    ProposalDraft,
    RegisteredTarget,
    ResponsePolicy,
)
from terminus.response.service import ResponseContractService
from terminus.response.storage import (
    ResponseConflictError,
    ResponseDeniedError,
    ResponseNotFoundError,
    digest,
)
from terminus.storage.db import Database
from terminus.toolkit.models import (
    EvidenceReference,
    ScopedEffect,
    VerificationObservation,
    VerificationReport,
)


@dataclasses.dataclass
class Clock:
    value: datetime

    def __call__(self):
        return self.value


@pytest.fixture
def setup(tmp_path: Path):
    db = Database(str(tmp_path / "response.db"))
    clock = Clock(datetime.now(UTC))
    now = clock().isoformat()
    for actor in ("admin", "admin2", "planner", "viewer"):
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (actor, f"{actor}@example.com", "unused", actor, now),
        )
    for org in ("org", "other"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
        db.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                f"incident:{org}",
                org,
                f"alert:{org}",
                "high",
                "high",
                "Fixture",
                "[]",
                "triage",
                now,
            ),
        )
        for actor, role in (
            ("admin", "admin"),
            ("admin2", "admin"),
            ("planner", "member"),
            ("viewer", "viewer"),
        ):
            db.execute("INSERT INTO memberships VALUES(?,?,?)", (org, actor, role))
    service = ResponseContractService(db, clock=clock)
    policy = ResponsePolicy(
        org_id="org",
        incident_id="incident:org",
        version=1,
        provider_connection_id="fixture:provider",
        allowed_actions=("response.wazuh_ip_block",),
        allowed_target_ids=("target:host", "target:protected", "target:management"),
        max_duration_seconds=60,
        max_approval_ttl_seconds=300,
    )
    targets = tuple(
        RegisteredTarget(
            target_id=target,
            org_id="org",
            incident_id="incident:org",
            provider_connection_id=policy.provider_connection_id,
            protected=target == "target:protected",
            management=target == "target:management",
        )
        for target in policy.allowed_target_ids
    )
    service.install_policy("admin", policy, targets)
    task = service.records.create_incident_task(
        "org",
        "incident:org",
        "response",
        "response_planner",
        "Fixture response planning",
    )
    service.scheduler.enqueue_task("org", task.task_id)
    assert service.scheduler.acquire_coordinator("owner", lease_seconds=300)
    lease = service.scheduler.claim_next(
        "owner", "worker", ["response_planner"], lease_seconds=300
    )
    assert lease is not None
    parameter = ParameterBinding(
        action="response.wazuh_ip_block",
        target_ids=("target:host",),
        provider_connection_id=policy.provider_connection_id,
        policy_version=policy.policy_version,
        duration_seconds=60,
        undo_strategy="owned_resource_only",
    )
    evidence = service.records.create_evidence(
        "org",
        task.task_id,
        "response.parameters",
        clock(),
        content=parameter.model_dump(mode="json"),
    )
    draft = ProposalDraft(
        effect=ScopedEffect(
            action=parameter.action,
            target_ids=parameter.target_ids,
            parameter_evidence_id=evidence.evidence_id,
            duration_seconds=60,
            undo_strategy="owned_resource_only",
        ),
        evidence_ids=(evidence.evidence_id,),
        prerequisites=("Registered scope and human review",),
        expected_effect="Temporary fixture rule",
        anticipated_impact="Fixture only; no network impact",
        verification_requirements=("Independent endpoint and attacker path checks",),
        health_requirements=("Independent management and service checks",),
        approval_ttl_seconds=300,
    )
    service.scheduler.complete(lease, {"fixture_only": True, "status": "completed"})
    yield service, FixtureResponseDriver(service), draft, clock, lease, policy, targets
    db.close()


def _propose(setup, actor="planner", draft=None):
    service, _, default, _, lease, _, _ = setup
    return service.propose("org", lease.task_id, actor, draft or default)


def _approved(setup):
    service, *_ = setup
    view = _propose(setup)
    return service.decide("org", view["proposal"]["proposal_id"], "admin", "approve")


def _dispatched(setup, outcome="acknowledged"):
    _, driver, *_ = setup
    view = _approved(setup)
    return driver.dispatch("org", view["proposal"]["proposal_id"], outcome)


def _verification(setup, view):
    service, _, _, _, _, _, _ = setup
    intent = view["intent"]
    dispatched = datetime.fromisoformat(intent["dispatched_at"])
    task = service.records.create_incident_task(
        "org",
        "incident:org",
        "verification",
        "verification",
        "Independent fixture collection",
    )
    _ = service.records.transition_task("org", task.task_id, "queued", "running")
    _ = service.records.transition_task("org", task.task_id, "running", "completed")
    run = AgentRun(
        org_id="org",
        incident_id="incident:org",
        task_id=task.task_id,
        status="completed",
        created_at=dispatched + timedelta(seconds=1),
        started_at=dispatched + timedelta(seconds=1),
        updated_at=dispatched + timedelta(seconds=4),
        completed_at=dispatched + timedelta(seconds=4),
        result={"fixture_only": True},
    )
    service.records._insert(run)
    observations = []
    for kind in (
        "endpoint_effect",
        "attacker_path",
        "management_health",
        "service_health",
    ):
        content = {
            "fixture_only": True,
            "intent_id": intent["intent_id"],
            "proposal_digest": view["proposal_digest"],
            "kind": kind,
            "passed": True,
        }
        evidence = EvidenceRecord(
            org_id="org",
            incident_id="incident:org",
            task_id=task.task_id,
            source=f"fixture:{kind}",
            source_timestamp=dispatched + timedelta(seconds=2),
            collected_at=dispatched + timedelta(seconds=3),
            content=content,
            content_hash=digest({"content": content, "content_ref": None}),
        )
        service.records._insert(evidence)
        observations.append(
            VerificationObservation(
                kind=kind,
                collector_run_id=run.run_id,
                source_id=evidence.source,
                source_timestamp=evidence.source_timestamp,
                evidence=EvidenceReference(
                    evidence_id=evidence.evidence_id,
                    org_id="org",
                    incident_id="incident:org",
                    content_hash=evidence.content_hash,
                ),
                passed=True,
            )
        )
    return VerificationReport(
        org_id="org",
        incident_id="incident:org",
        proposal_digest=view["proposal_digest"],
        dispatch_run_id=intent["dispatch_run_id"],
        dispatched_at=dispatched,
        status="verified",
        observations=tuple(observations),
    )


def _rewrite_evidence(service, evidence_id, **updates):
    # A fixture-only damaged-database scenario bypasses the normal immutable
    # storage guard to prove admission independently rechecks content/hashes.
    service.db.execute("DROP TRIGGER IF EXISTS orchestration_evidence_no_update")
    evidence = service.records.get_evidence("org", evidence_id)
    values = evidence.model_dump() | updates
    if "content" in updates:
        values["content_hash"] = digest(
            {"content": values["content"], "content_ref": values["content_ref"]}
        )
    changed = EvidenceRecord.model_validate(values)
    service.db.execute(
        "UPDATE orchestration_evidence SET payload_json=? WHERE org_id=? AND evidence_id=?",
        (changed.model_dump_json(), "org", evidence_id),
    )


def test_scope_provider_policy_and_parameter_hash_are_server_derived(setup):
    service, _, draft, _, lease, policy, _ = setup
    view = _propose(setup)
    proposal = view["proposal"]
    assert (
        proposal["org_id"],
        proposal["incident_id"],
        proposal["task_id"],
        proposal["run_id"],
    ) == ("org", "incident:org", lease.task_id, lease.run_id)
    assert proposal["provider_connection_id"] == policy.provider_connection_id
    assert proposal["policy_version"] == policy.policy_version
    evidence = service.records.get_evidence("org", draft.effect.parameter_evidence_id)
    assert evidence.content_hash in proposal["prerequisites"][-1]
    assert view["state"] == "proposed"
    assert view["fixture_only"]
    assert not view["live_executed"]
    assert not view["live_verified"]
    assert view["intent"] is None
    for field in (
        "org_id",
        "incident_id",
        "task_id",
        "run_id",
        "provider_connection_id",
        "policy_version",
    ):
        with pytest.raises(ValidationError):
            ProposalDraft.model_validate_json(
                json.dumps(draft.model_dump(mode="json") | {field: "caller-override"})
            )


@pytest.mark.parametrize(
    "bad",
    [
        "target:protected",
        "target:management",
        "target:unknown",
        "203.0.113.9",
        "https://manager",
        "C:/Windows/System32",
    ],
)
def test_protected_management_unregistered_and_arbitrary_targets_denied(setup, bad):
    _, _, draft, *_ = setup
    altered = draft.model_copy(
        update={"effect": draft.effect.model_copy(update={"target_ids": (bad,)})}
    )
    with pytest.raises((ValueError, ValidationError)):
        _propose(setup, draft=altered)


@pytest.mark.parametrize(
    "bad",
    ["unknown_action", "irreversible", "duration", "provider", "policy", "command"],
)
def test_only_exact_catalog_effect_and_parameter_evidence_allowed(setup, bad):
    service, _, draft, *_ = setup
    if bad == "unknown_action":
        draft = draft.model_copy(
            update={
                "effect": draft.effect.model_copy(update={"action": "arbitrary.run"})
            }
        )
    elif bad == "irreversible":
        draft = draft.model_copy(
            update={
                "effect": draft.effect.model_copy(
                    update={"undo_strategy": "irreversible"}
                )
            }
        )
    else:
        evidence = service.records.get_evidence(
            "org", draft.effect.parameter_evidence_id
        )
        content = dict(evidence.content)
        field = {
            "duration": "duration_seconds",
            "provider": "provider_connection_id",
            "policy": "policy_version",
            "command": "command",
        }[bad]
        content[field] = 59 if bad == "duration" else "untrusted"
        _rewrite_evidence(service, evidence.evidence_id, content=content)
    with pytest.raises((ValueError, ValidationError)):
        _propose(setup, draft=draft)


@pytest.mark.parametrize("actor", ["planner", "viewer"])
def test_only_current_admin_can_approve(setup, actor):
    service, driver, *_ = setup
    view = _propose(setup)
    with pytest.raises(ResponseDeniedError):
        service.decide("org", view["proposal"]["proposal_id"], actor, "approve")
    with pytest.raises(ResponseDeniedError):
        driver.reserve("org", view["proposal"]["proposal_id"])
    assert service.db.fetchone("SELECT COUNT(*) AS n FROM response_intents")["n"] == 0


def test_admin_proposer_cannot_self_approve(setup):
    service, driver, *_ = setup
    view = _propose(setup, actor="admin")
    with pytest.raises(ResponseDeniedError):
        service.decide("org", view["proposal"]["proposal_id"], "admin", "approve")
    approved = service.decide(
        "org", view["proposal"]["proposal_id"], "admin2", "approve"
    )
    assert approved["approval"]["approver_id"] == "admin2"
    assert driver.reserve("org", view["proposal"]["proposal_id"])["state"] == "reserved"


def test_denial_is_immutable_and_cannot_create_intent(setup):
    service, driver, *_ = setup
    view = _propose(setup)
    proposal_id = view["proposal"]["proposal_id"]
    assert service.decide("org", proposal_id, "admin", "deny")["state"] == "denied"
    assert service.decide("org", proposal_id, "admin", "deny")["state"] == "denied"
    with pytest.raises(ResponseConflictError):
        service.decide("org", proposal_id, "admin", "approve")
    with pytest.raises(ResponseDeniedError):
        driver.reserve("org", proposal_id)


def test_expired_approval_cannot_reserve_or_dispatch(setup):
    service, driver, _, clock, *_ = setup
    view = _approved(setup)
    clock.value += timedelta(seconds=300)
    assert service.inspect("org", view["proposal"]["proposal_id"])["state"] == "expired"
    with pytest.raises(ResponseDeniedError):
        driver.reserve("org", view["proposal"]["proposal_id"])
    assert service.db.fetchone("SELECT COUNT(*) AS n FROM response_intents")["n"] == 0


@pytest.mark.parametrize(
    "revoked", ["admin", "planner", "policy", "running_lease", "coordinator"]
)
def test_revocation_or_stale_planner_ownership_prevents_effects(setup, revoked):
    service, driver, _, clock, lease, policy, targets = setup
    view = _approved(setup)
    if revoked in {"admin", "planner"}:
        service.db.execute(
            "DELETE FROM memberships WHERE org_id='org' AND user_id=?", (revoked,)
        )
    elif revoked == "policy":
        service.install_policy(
            "admin2",
            policy.model_copy(update={"version": 2, "enabled": False}),
            targets,
        )
    else:
        job = service.scheduler.get_job("org", lease.task_id)
        task = service.records.get_task("org", lease.task_id)
        run = service.records.get_agent_run("org", lease.run_id)
        service.db.execute(
            "UPDATE orchestration_tasks SET status='running',payload_json=? WHERE org_id='org' AND task_id=?",
            (
                task.model_copy(update={"status": "running"}).model_dump_json(),
                lease.task_id,
            ),
        )
        service.db.execute(
            "UPDATE orchestration_agent_runs SET status='running',payload_json=? WHERE org_id='org' AND run_id=?",
            (
                run.model_copy(update={"status": "running"}).model_dump_json(),
                lease.run_id,
            ),
        )
        job = job.model_copy(
            update={
                "status": "running",
                "worker_id": lease.worker_id,
                "lease_token": lease.lease_token,
                "coordinator_owner_id": lease.coordinator_owner_id,
                "coordinator_token": lease.coordinator_token,
                "lease_expires_at": clock() + timedelta(seconds=60),
            }
        )
        service.db.execute(
            "UPDATE orchestration_scheduler_jobs SET status='running',payload_json=? WHERE org_id='org' AND task_id=?",
            (job.model_dump_json(), lease.task_id),
        )
        if revoked == "running_lease":
            clock.value += timedelta(seconds=61)
        else:
            service.db.execute(
                "UPDATE orchestration_scheduler_coordinator SET lease_token='revoked'"
            )
    with pytest.raises((ResponseDeniedError, ValueError)):
        driver.reserve("org", view["proposal"]["proposal_id"])
    assert service.db.fetchone("SELECT COUNT(*) AS n FROM response_intents")["n"] == 0


def test_proposal_and_approval_are_immutable_and_digest_is_rechecked(setup):
    service, driver, *_ = setup
    view = _approved(setup)
    proposal_id = view["proposal"]["proposal_id"]
    with pytest.raises(sqlite3.IntegrityError):
        service.db.execute(
            "UPDATE response_proposals SET digest=? WHERE org_id='org' AND proposal_id=?",
            ("0" * 64, proposal_id),
        )
    with pytest.raises(sqlite3.IntegrityError):
        service.db.execute(
            "DELETE FROM response_decisions WHERE org_id='org' AND proposal_id=?",
            (proposal_id,),
        )
    # Simulate a damaged database below the API/storage boundary. Admission
    # independently validates the binding even if immutability is bypassed.
    service.db.execute("DROP TRIGGER response_decisions_immutable_update")
    binding = dict(view["approval"]) | {"proposal_digest": "0" * 64}
    service.db.execute(
        "UPDATE response_decisions SET binding_json=? WHERE org_id='org' AND proposal_id=?",
        (json.dumps(binding), proposal_id),
    )
    with pytest.raises(ResponseDeniedError):
        driver.reserve("org", proposal_id)


def test_changed_canonical_parameter_hash_cannot_authorize_intent(setup):
    service, driver, draft, *_ = setup
    view = _approved(setup)
    content = dict(
        service.records.get_evidence("org", draft.effect.parameter_evidence_id).content
    )
    content["duration_seconds"] = 30
    _rewrite_evidence(service, draft.effect.parameter_evidence_id, content=content)
    with pytest.raises(ResponseDeniedError):
        driver.reserve("org", view["proposal"]["proposal_id"])


@pytest.mark.parametrize(
    "bad", ["foreign_incident", "foreign_tenant", "missing", "hash"]
)
def test_proposals_require_canonical_same_incident_citations(setup, bad):
    service, _, draft, _, lease, *_ = setup
    if bad == "hash":
        _rewrite_evidence(
            service, draft.effect.parameter_evidence_id, content_hash="0" * 64
        )
    elif bad == "missing":
        draft = draft.model_copy(
            update={"evidence_ids": (*draft.evidence_ids, "missing")}
        )
    else:
        org = "other" if bad == "foreign_tenant" else "org"
        incident = "incident:other"
        if org == "org":
            service.db.execute(
                "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "incident:second",
                    "org",
                    "second",
                    "high",
                    "high",
                    "Fixture",
                    "[]",
                    "triage",
                    datetime.now(UTC).isoformat(),
                ),
            )
            incident = "incident:second"
        foreign = service.records.create_incident_task(
            org, incident, "endpoint", "endpoint", "Foreign fixture"
        )
        evidence = service.records.create_evidence(
            org,
            foreign.task_id,
            "fixture",
            datetime.now(UTC),
            content={"fixture_only": True},
        )
        draft = draft.model_copy(
            update={"evidence_ids": (*draft.evidence_ids, evidence.evidence_id)}
        )
    with pytest.raises((ResponseDeniedError, OrchestrationNotFoundError)):
        service.propose("org", lease.task_id, "planner", draft)


def test_intent_committed_before_fixture_io_and_ack_is_not_verification(
    setup, monkeypatch
):
    service, driver, *_ = setup
    view = _approved(setup)
    original = driver._apply
    seen = []

    def observed(org, intent_id):
        assert not service.db._get_connection().in_transaction
        intent = service.store.intent(org, intent_id)
        assert intent["state"] == "in_flight"
        assert (
            service.records.get_agent_run(org, intent["dispatch_run_id"]).status
            == "running"
        )
        seen.append(intent_id)
        original(org, intent_id)

    monkeypatch.setattr(driver, "_apply", observed)
    done = driver.dispatch("org", view["proposal"]["proposal_id"])
    assert len(seen) == 1
    assert done["state"] == "acknowledged"
    assert not done["live_verified"]
    assert not done["live_executed"]
    assert done["verification"] is None
    assert (
        driver.dispatch("org", view["proposal"]["proposal_id"])["state"]
        == "acknowledged"
    )
    assert len(seen) == 1


def test_concurrent_reservation_and_dispatch_produce_one_intent_and_resource(setup):
    service, _, _, clock, *_ = setup
    view = _approved(setup)
    proposal_id = view["proposal"]["proposal_id"]
    others = [
        FixtureResponseDriver(
            ResponseContractService(Database(service.db.db_path), clock=clock)
        )
        for _ in range(4)
    ]
    with ThreadPoolExecutor(max_workers=4) as pool:
        intents = list(pool.map(lambda d: d.reserve("org", proposal_id), others))
    assert len({intent["intent_id"] for intent in intents}) == 1
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda d: d.dispatch("org", proposal_id), others))
    assert service.inspect("org", proposal_id)["state"] == "acknowledged"
    assert service.db.fetchone("SELECT COUNT(*) AS n FROM response_intents")["n"] == 1
    assert (
        service.db.fetchone("SELECT COUNT(*) AS n FROM response_fixture_receipts")["n"]
        == 1
    )
    assert (
        service.db.fetchone("SELECT COUNT(*) AS n FROM response_owned_resources")["n"]
        == 1
    )
    for driver in others:
        driver.db.close()


@pytest.mark.parametrize(
    "outcome",
    [
        "unknown_before_apply",
        "unknown_after_apply",
        "crash_before_apply",
        "crash_after_apply",
    ],
)
def test_unknown_restart_requires_reconciliation_and_never_replays(setup, outcome):
    service, _, _, clock, *_ = setup
    view = _dispatched(setup, outcome)
    proposal_id, intent_id = (
        view["proposal"]["proposal_id"],
        view["intent"]["intent_id"],
    )
    restarted = ResponseContractService(Database(service.db.db_path), clock=clock)
    driver = FixtureResponseDriver(restarted)
    assert driver.recover_interrupted("org") == (
        1 if outcome.startswith("crash") else 0
    )
    before = service.db.fetchone("SELECT COUNT(*) AS n FROM response_fixture_receipts")[
        "n"
    ]
    assert driver.dispatch("org", proposal_id)["state"] == "unknown"
    assert (
        service.db.fetchone("SELECT COUNT(*) AS n FROM response_fixture_receipts")["n"]
        == before
    )
    reconciled = driver.reconcile("org", intent_id)
    assert reconciled["state"] == (
        "acknowledged" if outcome.endswith("after_apply") else "unknown"
    )
    assert not reconciled["live_verified"]
    assert driver.recover_interrupted("org") == 0
    restarted.db.close()


def test_independent_persisted_checks_only_verify_the_fixture(setup):
    service, driver, *_ = setup
    view = _dispatched(setup)
    report = _verification(setup, view)
    done = driver.verify("org", view["intent"]["intent_id"], report)
    assert done["state"] == "fixture_verified"
    assert done["fixture_only"]
    assert not done["live_verified"]
    assert done["verification"]["fixture_only"]
    assert done["verification"]["report"]["status"] == "verified"
    restarted = ResponseContractService(
        Database(service.db.db_path), clock=service.clock
    )
    assert (
        restarted.inspect("org", view["proposal"]["proposal_id"])["state"]
        == "fixture_verified"
    )
    restarted.db.close()


@pytest.mark.parametrize(
    "bad",
    [
        "digest",
        "dispatch_run",
        "dispatch_time",
        "org",
        "incident",
        "source",
        "timestamp",
        "hash",
        "collector_run",
        "evidence_support",
        "pre_dispatch",
        "collector_scope",
    ],
)
def test_verification_rechecks_persisted_run_source_hash_times_and_support(setup, bad):
    service, driver, *_ = setup
    view = _dispatched(setup)
    report = _verification(setup, view)
    observation = report.observations[0]
    if bad in {"digest", "dispatch_run", "dispatch_time", "org", "incident"}:
        field = {
            "digest": "proposal_digest",
            "dispatch_run": "dispatch_run_id",
            "dispatch_time": "dispatched_at",
            "org": "org_id",
            "incident": "incident_id",
        }[bad]
        value = (
            "0" * 64
            if bad == "digest"
            else report.dispatched_at + timedelta(seconds=1)
            if bad == "dispatch_time"
            else "foreign"
        )
        report = report.model_copy(update={field: value})
    elif bad == "evidence_support":
        evidence = service.records.get_evidence("org", observation.evidence.evidence_id)
        content = dict(evidence.content) | {"passed": False}
        _rewrite_evidence(service, evidence.evidence_id, content=content)
        updated = service.records.get_evidence("org", evidence.evidence_id)
        observation = observation.model_copy(
            update={
                "evidence": observation.evidence.model_copy(
                    update={"content_hash": updated.content_hash}
                )
            }
        )
    elif bad == "pre_dispatch":
        _rewrite_evidence(
            service,
            observation.evidence.evidence_id,
            collected_at=report.dispatched_at - timedelta(seconds=1),
        )
    elif bad == "collector_scope":
        collector = service.records.get_agent_run("org", observation.collector_run_id)
        changed = collector.model_copy(update={"incident_id": "incident:other"})
        service.db.execute(
            "UPDATE orchestration_agent_runs SET payload_json=? WHERE org_id='org' AND run_id=?",
            (changed.model_dump_json(), collector.run_id),
        )
    else:
        values = {
            "source": {"source_id": "fixture:other"},
            "timestamp": {
                "source_timestamp": observation.source_timestamp + timedelta(seconds=1)
            },
            "hash": {
                "evidence": observation.evidence.model_copy(
                    update={"content_hash": "0" * 64}
                )
            },
            "collector_run": {"collector_run_id": report.dispatch_run_id},
        }[bad]
        observation = observation.model_copy(update=values)
    report = report.model_copy(
        update={"observations": (observation, *report.observations[1:])}
    )
    with pytest.raises((ValueError, OrchestrationNotFoundError)):
        driver.verify("org", view["intent"]["intent_id"], report)
    assert (
        service.inspect("org", view["proposal"]["proposal_id"])["state"]
        == "acknowledged"
    )


def test_ack_or_reused_evidence_cannot_establish_independent_verification(setup):
    _, driver, *_ = setup
    view = _dispatched(setup)
    report = _verification(setup, view)
    ack = report.observations[0].model_copy(update={"kind": "provider_ack"})
    with pytest.raises(ValidationError):
        driver.verify(
            "org",
            view["intent"]["intent_id"],
            report.model_copy(update={"observations": (ack,)}),
        )
    duplicate = report.observations[1].model_copy(
        update={"evidence": report.observations[0].evidence}
    )
    with pytest.raises(ValidationError):
        driver.verify(
            "org",
            view["intent"]["intent_id"],
            report.model_copy(
                update={
                    "observations": (
                        report.observations[0],
                        duplicate,
                        *report.observations[2:],
                    )
                }
            ),
        )


def test_owned_undo_and_expiry_do_not_touch_other_resources(setup):
    service, driver, _, clock, *_ = setup
    first = _dispatched(setup)
    second = _dispatched(setup)
    with pytest.raises(ResponseNotFoundError):
        driver.undo("other", first["intent"]["intent_id"], "admin")
    with pytest.raises(ResponseDeniedError):
        driver.undo("org", first["intent"]["intent_id"], "planner")
    assert (
        driver.undo("org", first["intent"]["intent_id"], "admin")["state"] == "undone"
    )
    assert (
        driver.undo("org", first["intent"]["intent_id"], "admin")["state"] == "undone"
    )
    assert (
        service.inspect("org", second["proposal"]["proposal_id"])["state"]
        == "acknowledged"
    )
    assert driver.expire_owned_resources("org") == 0
    clock.value += timedelta(seconds=60)
    assert driver.expire_owned_resources("org") == 1
    assert driver.expire_owned_resources("org") == 0
    assert (
        service.inspect("org", second["proposal"]["proposal_id"])["state"] == "expired"
    )
    with pytest.raises(ResponseDeniedError):
        driver.verify(
            "org", second["intent"]["intent_id"], _verification(setup, second)
        )


def test_undo_cannot_remove_resource_with_changed_ownership(setup):
    service, driver, *_ = setup
    view = _dispatched(setup)
    service.db.execute(
        "UPDATE response_owned_resources SET proposal_digest=? WHERE org_id='org' AND intent_id=?",
        ("0" * 64, view["intent"]["intent_id"]),
    )
    with pytest.raises(ResponseDeniedError):
        driver.undo("org", view["intent"]["intent_id"], "admin")
    assert (
        service.db.fetchone("SELECT state FROM response_owned_resources")["state"]
        == "owned"
    )


def test_inconclusive_or_changed_receipt_keeps_unknown_and_blocks_manual_undo(setup):
    service, driver, *_ = setup
    view = _dispatched(setup, "unknown_after_apply")
    intent_id = view["intent"]["intent_id"]
    with pytest.raises(ResponseDeniedError):
        driver.undo("org", intent_id, "admin")
    service.db.execute(
        "UPDATE response_fixture_receipts SET resource_id='fixture-resource:unowned' WHERE org_id='org' AND intent_id=?",
        (intent_id,),
    )
    assert driver.reconcile("org", intent_id)["state"] == "unknown"
    assert driver.dispatch("org", view["proposal"]["proposal_id"])["state"] == "unknown"
    assert (
        service.db.fetchone("SELECT COUNT(*) AS n FROM response_fixture_receipts")["n"]
        == 1
    )


def test_original_owned_expiry_remains_safe_after_approval_and_policy_revocation(setup):
    service, driver, _, clock, _, policy, targets = setup
    view = _dispatched(setup)
    service.db.execute("DELETE FROM memberships WHERE org_id='org' AND user_id='admin'")
    service.install_policy(
        "admin2", policy.model_copy(update={"version": 2, "enabled": False}), targets
    )
    clock.value += timedelta(seconds=60)
    assert driver.expire_owned_resources("org") == 1
    expired = service.inspect("org", view["proposal"]["proposal_id"])
    assert expired["state"] == "expired"
    assert not expired["live_executed"]
    assert not expired["verification_current"]


def test_altered_owned_expiry_does_not_remove_resources_early(setup):
    service, driver, _, clock, *_ = setup
    view = _dispatched(setup)
    service.db.execute(
        "UPDATE response_owned_resources SET expires_at=? WHERE org_id='org' AND intent_id=?",
        (clock().isoformat(), view["intent"]["intent_id"]),
    )
    with pytest.raises(ResponseDeniedError):
        driver.expire_owned_resources("org")
    assert (
        service.db.fetchone("SELECT state FROM response_owned_resources")["state"]
        == "owned"
    )


def test_wrong_role_and_foreign_task_never_create_proposals(setup):
    service, _, draft, *_ = setup
    wrong = service.records.create_incident_task(
        "org", "incident:org", "endpoint", "endpoint", "Wrong role fixture"
    )
    service.scheduler.enqueue_task("org", wrong.task_id)
    lease = service.scheduler.claim_next(
        "owner", "worker", ["endpoint"], lease_seconds=300
    )
    assert lease is not None
    service.scheduler.complete(lease, {"fixture_only": True})
    with pytest.raises(ResponseDeniedError):
        service.propose("org", wrong.task_id, "planner", draft)
    foreign = service.records.create_incident_task(
        "other",
        "incident:other",
        "response",
        "response_planner",
        "Other tenant fixture",
    )
    with pytest.raises(OrchestrationNotFoundError):
        service.propose("org", foreign.task_id, "planner", draft)
    assert service.db.fetchone("SELECT COUNT(*) AS n FROM response_proposals")["n"] == 0
