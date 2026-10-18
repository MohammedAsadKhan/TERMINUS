"""Autonomous lab admission, durable dispatch, deduplication and unknown holds."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from terminus.response.autonomous_lab import AutonomousLabController, LabAutonomousPolicy
from terminus.response.lab_observer import LabSSHObserver
from terminus.response.wazuh_transport import DispatchOutcome
from terminus.storage.db import Database
from terminus.toolkit.sources import ReadCollection, ReadObservation


@pytest.fixture
def setup(tmp_path, monkeypatch):
    now = datetime(2026, 10, 17, 22, tzinfo=UTC)
    clock = [now]
    db = Database(str(tmp_path / "auto.db"))
    db.execute("INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)", ("org", "Lab", now.isoformat()))
    db.execute("INSERT INTO users VALUES(?,?,?,?,?)", ("admin", "a@example.test", "hash", "Admin", now.isoformat()))
    db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", "admin", "admin"))
    observer = AsyncMock(return_value=True)
    transport = SimpleNamespace(dispatch=AsyncMock(return_value=DispatchOutcome(status="acknowledged", detail="unverified")))
    controller = AutonomousLabController(db, transport, observer, clock=lambda: clock[0])
    policy = LabAutonomousPolicy(org_id="org", actor_id="admin", enabled_until=now + timedelta(minutes=30))
    controller.enable(policy)

    async def sleep(seconds):
        clock[0] += timedelta(seconds=seconds)

    monkeypatch.setattr("terminus.response.autonomous_lab.asyncio.sleep", sleep)
    yield controller, db, transport, observer, clock, policy
    db.close()


def events(now, *, source="10.77.0.10", agent="001", count=3, prefix="event"):
    return ReadCollection(status="ok", coverage="complete", observations=tuple(
        ReadObservation(source_id="wazuh-indexer", source_event_id=f"{prefix}-{i}", source_timestamp=now,
                        data={"event_id": f"{prefix}-{i}", "alert": {"id": f"{prefix}-{i}", "timestamp": now.isoformat(),
                              "agent": {"id": agent, "ip": "10.77.0.20", "name": "terminus-target-a"},
                              "data": {"srcip": source}, "rule": {"groups": ["sshd", "authentication_failed"], "id": "5710"}}})
        for i in range(count)))


@pytest.mark.asyncio
async def test_durable_before_send_verified_recovery_and_cooldown(setup):
    controller, db, transport, _, clock, _ = setup

    async def dispatch(request):
        row = db.fetchone("SELECT state FROM autonomous_lab_intents WHERE intent_id=?", (request.intent_id,))
        assert row["state"] == "in_flight"
        assert str(request.source_ip) == "10.77.0.10"
        assert request.duration_seconds == 60
        return DispatchOutcome(status="acknowledged", detail="unverified")

    transport.dispatch.side_effect = dispatch
    collection = events(clock[0])
    assert await controller.process("org", collection) == "recovered"
    states = [row["state"] for row in db.fetchall("SELECT state FROM autonomous_lab_events ORDER BY seq")]
    assert states == ["in_flight", "acknowledged", "verified_blocked", "recovered"]
    assert await controller.process("org", collection) == "cooldown"
    assert transport.dispatch.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["stale", "future", "protected", "manager", "threshold", "partial"])
async def test_invalid_evidence_never_dispatches(setup, change):
    controller, _, transport, _, clock, _ = setup
    collection = events(clock[0], source="192.168.56.1" if change == "protected" else "10.77.0.10", agent="000" if change == "manager" else "001", count=2 if change == "threshold" else 3)
    if change in {"stale", "future"}:
        collection = events(clock[0] + timedelta(seconds=-121 if change == "stale" else 10))
    if change == "partial":
        collection = collection.model_copy(update={"status": "partial", "coverage": "incomplete"})
    await controller.process("org", collection)
    transport.dispatch.assert_not_awaited()


@pytest.mark.asyncio
async def test_acknowledgement_is_not_verification_and_unknown_never_retries(setup):
    controller, db, transport, observer, clock, _ = setup
    observer.side_effect = lambda stage, _: stage == "baseline"
    assert await controller.process("org", events(clock[0])) == "unknown"
    assert db.fetchone("SELECT state FROM autonomous_lab_intents")["state"] == "unknown"
    assert await controller.process("org", events(clock[0])) == "reconciliation_required"
    assert transport.dispatch.await_count == 1


@pytest.mark.asyncio
async def test_restart_retains_unknown_intent_and_denies_reenable(setup):
    controller, db, transport, observer, clock, policy = setup
    transport.dispatch.return_value = DispatchOutcome(status="unknown", detail="ambiguous")
    assert await controller.process("org", events(clock[0])) == "unknown"
    restarted = AutonomousLabController(db, transport, observer, clock=lambda: clock[0])
    with pytest.raises(ValueError, match="reconciliation"):
        restarted.enable(policy)
    assert await restarted.process("org", events(clock[0])) == "reconciliation_required"


@pytest.mark.asyncio
async def test_expiry_revocation_and_baseline_failure(setup):
    controller, db, transport, observer, clock, policy = setup
    observer.return_value = False
    assert await controller.process("org", events(clock[0])) == "baseline_unavailable"
    clock[0] = policy.enabled_until
    with pytest.raises(ValueError, match="expired"):
        await controller.process("org", events(clock[0]))
    clock[0] -= timedelta(seconds=1)
    db.execute("UPDATE memberships SET role='viewer' WHERE org_id='org'")
    with pytest.raises(ValueError, match="administrator"):
        await controller.process("org", events(clock[0]))
    transport.dispatch.assert_not_awaited()


@pytest.mark.parametrize("address", ["10.77.0.10", "127.0.0.1", "192.168.56.1"])
def test_observer_rejects_non_guest_management_targets(address):
    with pytest.raises(ValueError):
        LabSSHObserver(address)

@pytest.mark.asyncio
async def test_dispatch_exception_is_durable_unknown(setup):
    controller, db, transport, _, clock, _ = setup
    transport.dispatch.side_effect = TimeoutError()
    with pytest.raises(TimeoutError):
        await controller.process("org", events(clock[0]))
    assert db.fetchone("SELECT state FROM autonomous_lab_intents")["state"] == "unknown"


@pytest.mark.asyncio
async def test_quota_and_dedup_survive_cooldown(setup):
    controller, _, transport, _, clock, _ = setup
    original = events(clock[0])
    assert await controller.process("org", original) == "recovered"
    clock[0] += timedelta(seconds=301)
    # Same event identities cannot be reused even if timestamps are presented as fresh.
    assert await controller.process("org", events(clock[0])) == "duplicate_events"
    assert transport.dispatch.await_count == 1


@pytest.mark.asyncio
async def test_freshness_rechecked_after_slow_baseline(setup):
    controller, _, transport, observer, clock, _ = setup

    async def slow(stage, details):
        clock[0] += timedelta(seconds=121)
        return True

    observer.side_effect = slow
    assert await controller.process("org", events(clock[0])) == "stale_after_baseline"
    transport.dispatch.assert_not_awaited()

@pytest.mark.asyncio
@pytest.mark.parametrize(("stage", "reachable", "elements", "owned", "expected"), [
    ("blocked", False, ["10.77.0.10"], True, True),
    ("blocked", True, ["10.77.0.10"], True, False),
    ("blocked", False, [], True, False),
    ("blocked", False, ["10.77.0.10"], False, False),
    ("recovered", True, [], True, True),
    ("recovered", False, [], True, False),
])
async def test_independent_observer_requires_source_management_and_ownership(stage, reachable, elements, owned, expected):
    import hashlib
    import json

    observer = LabSSHObserver("192.168.56.105")
    details = {"intent_id": "test", "proposal_digest": "a" * 64}
    identity = hashlib.sha256(f"test:{'a' * 64}".encode()).hexdigest()
    table = "terminus_" + identity[:24]
    output = json.dumps({"nftables": [
        {"table": {"family": "inet", "name": table, "comment": identity if owned else "foreign"}},
        {"set": {"name": "blocked", "table": table, "elem": elements}},
    ]})
    observer._read = AsyncMock(side_effect=[(0, "terminus-target-a\n"), (0, "PROBE_STATUS:0" if reachable else "PROBE_STATUS:1"), (0, output)])
    assert await observer(stage, details) is expected


@pytest.mark.asyncio
async def test_cancellation_after_intent_leaves_unknown_without_retry(setup):
    import asyncio

    controller, db, transport, _, clock, _ = setup
    transport.dispatch.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await controller.process("org", events(clock[0]))
    assert db.fetchone("SELECT state FROM autonomous_lab_intents")["state"] == "unknown"


@pytest.mark.asyncio
async def test_revocation_during_baseline_prevents_dispatch(setup):
    controller, db, transport, observer, clock, _ = setup

    async def revoke(stage, details):
        db.execute("UPDATE memberships SET role='viewer' WHERE org_id='org'")
        return True

    observer.side_effect = revoke
    with pytest.raises(ValueError, match="administrator"):
        await controller.process("org", events(clock[0]))
    transport.dispatch.assert_not_awaited()

@pytest.mark.asyncio
async def test_reconciliation_of_unknown_does_not_invent_verified_block(setup):
    from terminus.response.autonomous_lab import reconcile_lab_actions

    controller, db, transport, observer, clock, _ = setup
    transport.dispatch.return_value = DispatchOutcome(status="unknown", detail="ambiguous")
    assert await controller.process("org", events(clock[0])) == "unknown"
    result = await reconcile_lab_actions(db, "org", "admin", observer, clock=lambda: clock[0])
    assert result[0]["state"] == "waiting_for_expiry"
    clock[0] += timedelta(seconds=90)
    result = await reconcile_lab_actions(db, "org", "admin", observer, clock=lambda: clock[0])
    assert result[0]["state"] == "recovered_unverified"
    assert transport.dispatch.await_count == 1
    assert not db.fetchone("SELECT 1 FROM autonomous_lab_events WHERE state='verified_blocked'")


@pytest.mark.asyncio
async def test_reconciliation_verifies_expiry_after_interruption(setup, monkeypatch):
    import asyncio
    from terminus.response.autonomous_lab import reconcile_lab_actions

    controller, db, transport, observer, clock, _ = setup

    async def interrupt(seconds):
        raise asyncio.CancelledError

    monkeypatch.setattr("terminus.response.autonomous_lab.asyncio.sleep", interrupt)
    with pytest.raises(asyncio.CancelledError):
        await controller.process("org", events(clock[0]))
    assert db.fetchone("SELECT state FROM autonomous_lab_intents")["state"] == "verified_blocked"
    clock[0] += timedelta(seconds=90)
    result = await reconcile_lab_actions(db, "org", "admin", observer, clock=lambda: clock[0])
    assert result[0]["state"] == "recovered"
    assert transport.dispatch.await_count == 1


@pytest.mark.asyncio
async def test_reconciliation_refuses_unobserved_recovery_and_tampering(setup):
    from terminus.response.autonomous_lab import reconcile_lab_actions

    controller, db, transport, observer, clock, _ = setup
    transport.dispatch.return_value = DispatchOutcome(status="unknown", detail="ambiguous")
    await controller.process("org", events(clock[0]))
    clock[0] += timedelta(seconds=90)
    observer.return_value = False
    assert (await reconcile_lab_actions(db, "org", "admin", observer, clock=lambda: clock[0]))[0]["state"] == "unresolved"
    db.execute("UPDATE autonomous_lab_intents SET proposal_digest=?", ("b" * 64,))
    with pytest.raises(ValueError, match="integrity"):
        await reconcile_lab_actions(db, "org", "admin", observer, clock=lambda: clock[0])

@pytest.mark.asyncio
async def test_durable_quota_cannot_be_reset_by_new_events(setup):
    controller, _, transport, observer, clock, _ = setup
    for cycle in range(3):
        assert await controller.process("org", events(clock[0], prefix=f"cycle-{cycle}")) == "recovered"
        clock[0] += timedelta(seconds=301)
    assert await controller.process("org", events(clock[0], prefix="over-quota")) == "quota_exhausted"
    assert transport.dispatch.await_count == 3
    # No additional baseline calls after durable quota admission denies the action.
    assert observer.await_count == 9


@pytest.mark.asyncio
async def test_two_controllers_cannot_dispatch_same_observations(setup):
    import asyncio

    controller, db, transport, observer, clock, _ = setup
    release = asyncio.Event()
    baseline_count = 0

    async def barrier(stage, details):
        nonlocal baseline_count
        if stage == "baseline":
            baseline_count += 1
            if baseline_count == 2:
                release.set()
            await release.wait()
        return True

    observer.side_effect = barrier
    second = AutonomousLabController(db, transport, observer, clock=lambda: clock[0])
    collection = events(clock[0])
    results = await asyncio.gather(controller.process("org", collection), second.process("org", collection))
    assert results.count("recovered") == 1
    assert transport.dispatch.await_count == 1
    assert db.fetchone("SELECT count(*) AS n FROM autonomous_lab_intents")["n"] == 1

@pytest.mark.asyncio
async def test_late_worker_cannot_overwrite_terminal_recovery(setup):
    controller, db, _, _, clock, _ = setup
    assert await controller.process("org", events(clock[0])) == "recovered"
    intent = db.fetchone("SELECT intent_id FROM autonomous_lab_intents")["intent_id"]
    controller._state(intent, "unknown")
    assert db.fetchone("SELECT state FROM autonomous_lab_intents")["state"] == "recovered"
