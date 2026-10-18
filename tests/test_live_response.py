"""Live decision boundary tests with fake transport, never installed effects."""

# pyright: basic
from datetime import UTC, datetime, timedelta

import pytest

from terminus.response.live import LiveResponseService, ResponseConflictError
from terminus.response.wazuh_transport import DispatchOutcome
from terminus.storage.db import Database
from terminus.toolkit.lab_import import import_authentication_incident
from terminus.toolkit.sources import ReadCollection, ReadObservation


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "live.db"))
    now = [datetime.now(UTC)]
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("org", "Org", now[0].isoformat()),
    )
    for user, role in [("admin", "admin"), ("member", "member")]:
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (user, user + "@example.test", "hash", user, now[0].isoformat()),
        )
        db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", user, role))
    observations = tuple(
        ReadObservation(
            source_id="wazuh-indexer",
            source_event_id=f"event-{i}",
            source_timestamp=now[0],
            data={
                "alert": {
                    "id": f"e-{i}",
                    "timestamp": now[0].isoformat(),
                    "agent": {
                        "id": "001",
                        "ip": "10.77.0.20",
                        "name": "terminus-target-a",
                    },
                    "rule": {
                        "id": "5710",
                        "description": "SSH failed",
                        "groups": ["sshd", "authentication_failed"],
                    },
                    "data": {"srcip": "10.77.0.10"},
                    "full_log": "Invalid user",
                }
            },
        )
        for i in range(3)
    )
    incident = import_authentication_incident(
        db,
        org_id="org",
        actor="admin",
        agent_id="001",
        collection=ReadCollection(
            status="ok", coverage="complete", observations=observations
        ),
    )
    now[0] = datetime.now(UTC)
    service = LiveResponseService(db, clock=lambda: now[0])
    service.takeover("org")
    proposal = service.refresh("org", incident)
    view = service.inspect("org", incident)
    fingerprint = view["proposals"][0]["digest"]
    yield db, service, incident, proposal, fingerprint, now
    db.close()


class Transport:
    def __init__(self):
        self.calls = []

    async def dispatch(self, request):
        self.calls.append(request)
        return DispatchOutcome(status="acknowledged", detail="fake accepted")


async def observer(phase, details):
    return True


def decide(setup, decision="approve", actor="admin", note=""):
    _, service, incident, proposal, fingerprint, _ = setup
    return service.decide("org", incident, proposal, actor, fingerprint, decision, note)


@pytest.mark.asyncio
async def test_approve_dispatch_verify_then_reconcile(setup):
    db, service, incident, _, _, now = setup
    transport = Transport()
    decide(setup)
    assert db.fetchone("SELECT COUNT(*) AS n FROM live_response_intents")["n"] == 0
    await service.tick("org", transport, observer)
    assert len(transport.calls) == 1
    assert service.inspect("org", incident)["intents"][0]["state"] == "verified_blocked"
    await service.tick("org", transport, observer)
    assert len(transport.calls) == 1
    now[0] += timedelta(seconds=80)
    await service.tick("org", transport, observer)
    assert service.inspect("org", incident)["intents"][0]["state"] == "recovered"
    assert (
        db.fetchone("SELECT status FROM incidents WHERE ticket_id=?", (incident,))[
            "status"
        ]
        == "OPEN"
    )


@pytest.mark.parametrize(
    ("decision", "note"), [("reject", "authorized test"), ("defer", "later")]
)
@pytest.mark.asyncio
async def test_reject_and_defer_never_dispatch(setup, decision, note):
    _, service, _, _, _, _ = setup
    transport = Transport()
    decide(setup, decision, note=note)
    await service.tick("org", transport, observer)
    assert not transport.calls


def test_permissions_digest_and_rejection_reason(setup):
    _, service, incident, proposal, _, _ = setup
    with pytest.raises(PermissionError):
        decide(setup, actor="member")
    with pytest.raises(ValueError, match="reason"):
        decide(setup, "reject")
    with pytest.raises(ResponseConflictError):
        service.decide("org", incident, proposal, "admin", "a" * 64, "approve")
    with pytest.raises(LookupError):
        service.inspect("other", incident)


def test_repeat_decision_idempotent_conflict_immutable(setup):
    db, *_ = setup
    decide(setup)
    decide(setup)
    assert (
        db.fetchone("SELECT COUNT(*) AS n FROM live_response_authorizations")["n"] == 1
    )
    with pytest.raises(ResponseConflictError):
        decide(setup, "reject", note="changed mind")


def test_stale_and_worker_unavailable(setup):
    db, service, incident, _, _, now = setup
    db.execute("DELETE FROM live_response_runtime")
    assert (
        service.inspect("org", incident)["proposals"][0]["capability"]
        == "Connector unavailable"
    )
    with pytest.raises(ResponseConflictError):
        decide(setup)
    now[0] += timedelta(seconds=121)
    service.takeover("org")
    assert (
        service.inspect("org", incident)["proposals"][0]["capability"]
        == "Needs fresh evidence"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("stop", ["revoke", "close", "expiry", "membership"])
async def test_autonomy_revocation_closure_expiry_membership(setup, stop):
    db, service, incident, _, _, now = setup
    transport = Transport()
    decide(setup, "autonomy")
    if stop == "revoke":
        service.stop("org", incident, "admin")
    elif stop == "close":
        db.execute(
            "UPDATE incidents SET status='RESOLVED' WHERE ticket_id=?", (incident,)
        )
        db.execute("UPDATE incidents SET status='OPEN' WHERE ticket_id=?", (incident,))
    elif stop == "expiry":
        now[0] += timedelta(minutes=31)
    else:
        db.execute("DELETE FROM memberships WHERE user_id='admin'")
    await service.tick("org", transport, observer)
    assert not transport.calls


@pytest.mark.asyncio
async def test_durable_before_send_and_unknown_no_retry(setup):
    db, service, incident, _, _, now = setup
    decide(setup)

    class Crash:
        async def dispatch(self, request):
            assert (
                db.fetchone("SELECT state FROM live_response_intents")["state"]
                == "in_flight"
            )
            raise RuntimeError("transport interrupted")

    with pytest.raises(RuntimeError):
        await service.tick("org", Crash(), observer)
    assert service.inspect("org", incident)["intents"][0]["state"] == "unknown"
    transport = Transport()
    await service.tick("org", transport, observer)
    assert not transport.calls
    now[0] += timedelta(seconds=80)
    await service.tick("org", transport, observer)
    assert (
        service.inspect("org", incident)["intents"][0]["state"]
        == "recovered_unverified"
    )


@pytest.mark.asyncio
async def test_slow_baseline_rechecks_freshness(setup):
    _, service, _, _, _, now = setup
    decide(setup)
    transport = Transport()

    async def slow(phase, details):
        now[0] += timedelta(seconds=121)
        return True

    await service.tick("org", transport, slow)
    assert not transport.calls


def test_file_events_never_become_ip_block(setup):
    db, service, incident, _, _, _ = setup
    db.execute(
        "INSERT INTO incidents(ticket_id,org_id,alert_id,rule_id,rule_description,severity,confidence,summary,recommended_actions,agent_name,full_log,policy_tier,status,created_at,updated_at) SELECT 'FIM-REVIEW',org_id,alert_id,rule_id,rule_description,severity,confidence,summary,recommended_actions,agent_name,full_log,policy_tier,status,created_at,updated_at FROM incidents WHERE ticket_id=?",
        (incident,),
    )
    incident = "FIM-REVIEW"
    # An incident with no authenticated SSH source records remains review-only.
    service.refresh("org", incident)
    view = service.inspect("org", incident)
    assert view["proposals"][0]["capability"] == "Unsupported action"


def test_http_decision_authentication_scope_and_extra_commands(setup):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from terminus.auth.models import User
    from terminus.core.ids import UserId
    from terminus.orgs.storage import SqliteMembershipStore
    from terminus.server.deps import get_auth_service, get_membership_store
    from terminus.server.response_api import router, get_live_response_service

    db, service, incident, proposal, fingerprint, now = setup

    class Auth:
        def verify(self, token):
            if token not in {"admin", "member"}:
                raise ValueError("bad token")
            return User(
                user_id=UserId(token),
                email=token + "@example.test",
                password_hash="hash",
                display_name=token,
                created_at=now[0],
            )

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_auth_service] = Auth
    app.dependency_overrides[get_membership_store] = lambda: SqliteMembershipStore(db)
    app.dependency_overrides[get_live_response_service] = lambda: service
    base = f"/incidents/{incident}/response"
    with TestClient(app) as client:
        assert client.get(base).status_code == 401
        headers = {"Authorization": "Bearer admin", "X-Org-ID": "org"}
        assert client.get(base, headers=headers).status_code == 200
        assert (
            client.get(base, headers={**headers, "X-Org-ID": "foreign"}).status_code
            == 403
        )
        payload = {"digest": fingerprint, "decision": "approve"}
        assert (
            client.post(
                base + f"/{proposal}/decision",
                headers={**headers, "Authorization": "Bearer member"},
                json=payload,
            ).status_code
            == 403
        )
        assert (
            client.post(
                base + f"/{proposal}/decision",
                headers=headers,
                json={**payload, "command": "arbitrary-shell"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                base + f"/{proposal}/decision", headers=headers, json=payload
            ).status_code
            == 202
        )


def test_revisions_revoke_old_and_require_different_human_approver(setup):
    _, service, incident, proposal, fingerprint, _ = setup
    decide(setup)
    view = service.revise("org", incident, proposal, "admin", fingerprint, 90)
    revision = view["proposals"][0]
    assert revision["proposal_id"] != proposal
    assert view["authorizations"][0]["revoked_at"]
    assert view["proposals"][1]["capability"] == "Superseded"
    with pytest.raises(PermissionError, match="self-approve"):
        service.decide(
            "org",
            incident,
            revision["proposal_id"],
            "admin",
            revision["digest"],
            "approve",
        )


@pytest.mark.asyncio
async def test_concurrent_workers_reserve_one_effect(setup):
    import asyncio

    db, service, _, _, _, now = setup
    decide(setup)
    other = LiveResponseService(Database(db.db_path), clock=lambda: now[0])
    transport = Transport()
    await asyncio.gather(
        service.tick("org", transport, observer), other.tick("org", transport, observer)
    )
    assert len(transport.calls) == 1
    other.db.close()


@pytest.mark.asyncio
async def test_offline_connector_still_reconciles_without_dispatch(setup):
    _, service, incident, _, _, now = setup
    decide(setup)
    transport = Transport()
    await service.tick("org", transport, observer)
    now[0] += timedelta(seconds=80)
    await service.tick("org", transport, observer, available=False)
    assert service.inspect("org", incident)["intents"][0]["state"] == "recovered"
    assert len(transport.calls) == 1


@pytest.mark.asyncio
async def test_autonomy_links_only_matching_new_records_to_same_incident(setup):
    from terminus.orchestration.storage import OrchestrationStore

    _, service, incident, _, _, now = setup
    decide(setup, "autonomy")
    now[0] += timedelta(seconds=1)
    stamp = now[0]
    items = tuple(
        ReadObservation(
            source_id="wazuh-indexer",
            source_event_id=f"future-{i}",
            source_timestamp=stamp,
            data={
                "alert": {
                    "id": f"future-{i}",
                    "timestamp": stamp.isoformat(),
                    "agent": {"id": "001", "ip": "10.77.0.20"},
                    "rule": {"groups": ["sshd", "authentication_failed"]},
                    "data": {"srcip": source},
                }
            },
        )
        for i, source in enumerate(["10.77.0.10", "192.168.56.1"])
    )
    collection = ReadCollection(status="ok", coverage="complete", observations=items)
    assert service.link_fresh_observations("org", collection) == 1
    assert service.link_fresh_observations("org", collection) == 0
    records = OrchestrationStore(service.db).list_evidence("org", incident_id=incident)
    assert any(
        r.content.get("source_event_id") == "future-0"
        for r in records
        if isinstance(r.content, dict)
    )
    assert not any(
        r.content.get("source_event_id") == "future-1"
        for r in records
        if isinstance(r.content, dict)
    )


@pytest.mark.asyncio
async def test_autonomy_repeat_cooldown_replay_and_durable_quota(setup):
    _, service, incident, _, _, now = setup
    decide(setup, "autonomy")
    transport = Transport()
    await service.tick("org", transport, observer)
    assert len(transport.calls) == 1
    for batch in range(1, 4):
        now[0] += timedelta(seconds=301)
        stamp = now[0]
        collection = ReadCollection(
            status="ok",
            coverage="complete",
            observations=tuple(
                ReadObservation(
                    source_id="wazuh-indexer",
                    source_event_id=f"batch-{batch}-{i}",
                    source_timestamp=stamp,
                    data={
                        "alert": {
                            "id": f"batch-{batch}-{i}",
                            "timestamp": stamp.isoformat(),
                            "agent": {"id": "001", "ip": "10.77.0.20"},
                            "rule": {
                                "id": "5710",
                                "groups": ["sshd", "authentication_failed"],
                            },
                            "data": {"srcip": "10.77.0.10"},
                        }
                    },
                )
                for i in range(3)
            ),
        )
        assert service.link_fresh_observations("org", collection) == 3
        await service.tick("org", transport, observer)
        assert len(transport.calls) == min(batch + 1, 3)
        await service.tick("org", transport, observer)
        assert len(transport.calls) == min(batch + 1, 3)
    assert len(service.inspect("org", incident)["intents"]) == 3


@pytest.mark.asyncio
async def test_revocation_during_baseline_prevents_dispatch(setup):
    _, service, incident, _, _, _ = setup
    decide(setup)
    transport = Transport()

    async def revoke(phase, details):
        service.stop("org", incident, "admin")
        return True

    await service.tick("org", transport, revoke)
    assert not transport.calls


def test_console_takeover_fences_standalone_controller(setup):
    from terminus.response.autonomous_lab import (
        AutonomousLabController,
        LabAutonomousPolicy,
    )

    db, _, _, _, _, now = setup
    legacy = AutonomousLabController(db, Transport(), observer, clock=lambda: now[0])
    with pytest.raises(ValueError, match="Console response worker"):
        legacy.enable(
            LabAutonomousPolicy(
                org_id="org",
                actor_id="admin",
                enabled_until=now[0] + timedelta(minutes=30),
            )
        )


def test_adapter_cannot_be_shared_across_tenants(setup):
    _, service, _, _, _, _ = setup
    with pytest.raises(ResponseConflictError, match="another organization"):
        service.takeover("foreign")


def test_source_label_alone_is_not_live_execution_provenance(setup):
    db, service, incident, _, _, _ = setup
    db.execute("DELETE FROM live_response_source_receipts")
    service.refresh("org", incident)
    assert (
        service.inspect("org", incident)["proposals"][0]["capability"]
        == "Unsupported action"
    )
    with pytest.raises(ResponseConflictError):
        decide(setup)


@pytest.mark.asyncio
async def test_human_revision_autonomy_retains_reviewed_duration(setup):
    db, service, incident, proposal, fingerprint, _ = setup
    view = service.revise("org", incident, proposal, "admin", fingerprint, 90)
    revised = view["proposals"][0]
    db.execute("UPDATE memberships SET role='admin' WHERE user_id='member'")
    service.decide(
        "org", incident, revised["proposal_id"], "member", revised["digest"], "autonomy"
    )
    transport = Transport()
    await service.tick("org", transport, observer)
    assert len(transport.calls) == 1
    assert transport.calls[0].duration_seconds == 90


def test_polling_intake_prepares_pending_incident_without_authorization(setup):
    db, service, _, _, _, now = setup
    stamp = now[0]
    collection = ReadCollection(
        status="ok",
        coverage="complete",
        observations=tuple(
            ReadObservation(
                source_id="wazuh-indexer",
                source_event_id=f"intake-{i}",
                source_timestamp=stamp,
                data={
                    "alert": {
                        "id": f"intake-{i}",
                        "timestamp": stamp.isoformat(),
                        "agent": {"id": "001", "ip": "10.77.0.20"},
                        "rule": {
                            "id": "5710",
                            "description": "SSH failure",
                            "groups": ["sshd", "authentication_failed"],
                        },
                        "data": {"srcip": "10.77.0.10"},
                    }
                },
            )
            for i in range(3)
        ),
    )
    incident = service.ingest("org", "admin", collection)
    assert incident
    assert service.inspect("org", incident)["proposals"][0]["capability"] == "Ready"
    assert not service.inspect("org", incident)["authorizations"]
    assert service.ingest("org", "admin", collection) is None
    assert db.fetchone("SELECT COUNT(*) AS n FROM live_response_intents")["n"] == 0


@pytest.mark.asyncio
async def test_worker_keeps_healthy_quiet_collector_available(setup, monkeypatch):
    from argparse import Namespace
    from scripts import run_response_worker as worker

    db, _, _, _, _, now = setup

    class Reader:
        def __init__(self, *args, **kwargs):
            pass

        async def read(self, query, resource):
            if query.event_kind == "inventory":
                return ReadCollection(
                    status="ok",
                    coverage="complete",
                    observations=(
                        ReadObservation(
                            source_id="wazuh-manager",
                            source_event_id="agent:001",
                            source_timestamp=now[0],
                            data={
                                "name": "terminus-target-a",
                                "connectivity": "active",
                            },
                        ),
                    ),
                )
            return ReadCollection(status="empty", coverage="complete")

        async def aclose(self):
            pass

    monkeypatch.setattr(worker, "Database", lambda _: db)
    monkeypatch.setattr(worker, "WazuhManagerReader", Reader)
    monkeypatch.setattr(worker, "WazuhIndexerReader", Reader)
    monkeypatch.setattr(worker, "LabSSHObserver", lambda _: observer)
    transport = Transport()
    monkeypatch.setattr(worker, "WazuhResponseTransport", lambda *a, **k: transport)
    monkeypatch.setattr("builtins.input", lambda _: "reader")
    monkeypatch.setattr(worker.getpass, "getpass", lambda _: "test-credential")

    async def stop_after_tick(_):
        assert LiveResponseService(db).ready("org")
        assert not transport.calls
        raise asyncio.CancelledError

    import asyncio

    monkeypatch.setattr(worker.asyncio, "sleep", stop_after_tick)
    with pytest.raises(asyncio.CancelledError):
        await worker.run(
            Namespace(
                database="unused",
                org="org",
                actor="admin",
                kali_management_ip="192.168.56.102",
            )
        )
