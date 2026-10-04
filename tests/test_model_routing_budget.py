# ruff: noqa: F811
"""M05: financial admission inside capability routing (fixture transports only)."""

from __future__ import annotations

import asyncio
import json

import httpx2
import pytest

from terminus.model_gateway.ledger import (
    ModelBudgetStore,
    UsageReport,
    window_key_for,
)
from terminus.model_gateway.policy import ModelPolicyWrite
from terminus.model_gateway.routing import (
    ModelRoutingDeniedError,
    ModelRoutingService,
)
from terminus.storage.db import Database
from tests.test_model_admission import NOW, client, reply, setup  # noqa: F401
from tests.test_model_routing import DOWN, GOOD, factory, rows

WINDOW = window_key_for(NOW)
MAX_OUT = 100


def usage_reply(**usage):
    body = reply()
    body["usage"] = usage
    return body


def make(fixture, *, limit=1_000_000_000, priced=("local", "hosted"), **rates):
    """Router plus its store; $1/Mtok in and out unless rates override."""
    service, _, _, local, hosted, _, _, db = fixture
    store = ModelBudgetStore(db, clock=lambda: NOW)
    prices = {
        "input_per_mtok_micro_usd": 1_000_000,
        "output_per_mtok_micro_usd": 1_000_000,
        **rates,
    }
    for name, connection in (("local", local), ("hosted", hosted)):
        if name in priced:
            _ = store.put_price(
                "org", "admin", connection.connection_id, "fixture-model", **prices
            )
    if limit is not None:
        _ = store.put_budget("org", "admin", WINDOW, limit_micro_usd=limit)
    return ModelRoutingService(service, store), store


async def route(router, fixture, factory_, **kwargs):
    _, lease, evidence, *_ = fixture
    kwargs.setdefault("max_output_tokens", MAX_OUT)
    return await router.route_fixture(
        lease, "member", (evidence.evidence_id,), factory_, **kwargs
    )


async def bound(fixture, connection=None):
    """Reservation bound for one attempt at $1/Mtok: bytes + max output tokens."""
    service, lease, evidence, local, *_ = fixture
    call = await service.prepare(
        lease,
        "member",
        (connection or local).connection_id,
        "fixture-model",
        (evidence.evidence_id,),
        max_output_tokens=MAX_OUT,
    )
    return len(call.request.model_dump_json().encode()) + MAX_OUT


def reservations(db):
    return db.fetchall(
        "SELECT reservation_id,state,connection_id,reserved_micro_usd,"
        "actual_cost_micro_usd FROM model_reservations ORDER BY created_at, rowid"
    )


@pytest.mark.asyncio
async def test_reservation_is_committed_before_provider_io(setup):
    db = setup[7]
    router, _ = make(setup)
    seen = []

    def transport(req):
        seen.append(reservations(db))
        return httpx2.Response(200, json=reply())

    result = await route(router, setup, factory(setup[3], setup[4], transport))
    assert len(seen) == 1
    assert [r["state"] for r in seen[0]] == ["reserved"]
    assert seen[0][0]["reservation_id"] == result.selected.reservation_id
    assert seen[0][0]["reserved_micro_usd"] > 0


@pytest.mark.asyncio
async def test_known_usage_settles_with_price_snapshot_cost(setup):
    db = setup[7]
    router, store = make(
        setup,
        input_per_mtok_micro_usd=1_000_000,
        output_per_mtok_micro_usd=2_000_000,
        cached_input_per_mtok_micro_usd=250_000,
        reasoning_per_mtok_micro_usd=4_000_000,
    )
    body = usage_reply(
        prompt_tokens=1000,
        completion_tokens=500,
        total_tokens=1500,
        prompt_tokens_details={"cached_tokens": 400},
        completion_tokens_details={"reasoning_tokens": 100},
    )
    result = await route(
        router,
        setup,
        factory(setup[3], setup[4], lambda r: httpx2.Response(200, json=body)),
    )
    # 600*1 + 400*0.25 + 400*2 + 100*4 = 1900 micro-USD per million tokens x1e-6.
    attempt = result.selected
    assert (attempt.cost_known, attempt.cost_micro_usd, attempt.usage_known) == (
        True,
        1900,
        True,
    )
    row = reservations(db)[0]
    assert (row["state"], row["actual_cost_micro_usd"]) == ("settled", 1900)
    summary = store.usage_summary("org", "member", WINDOW)
    assert summary.known_cost_micro_usd == 1900
    assert summary.unknown_cost_count == 0


@pytest.mark.asyncio
async def test_missing_price_excludes_candidate_without_io(setup):
    db = setup[7]
    router, _ = make(setup, priced=())
    calls = []
    with pytest.raises(ModelRoutingDeniedError):
        await route(
            router,
            setup,
            factory(setup[3], setup[4], lambda r: calls.append(r) or GOOD(r)),
        )
    assert calls == []
    assert reservations(db) == []
    # Unclassified evidence is local-only, so hosted is an admission denial.
    assert [r["outcome"] for r in rows(db) if r["kind"] == "excluded"] == [
        "budget_denied",
        "admission_denied",
    ]
    assert rows(db)[-1]["outcome"] == "no_eligible_route"


@pytest.mark.asyncio
async def test_missing_budget_denies_without_io(setup):
    router, _ = make(setup, limit=None)
    calls = []
    with pytest.raises(ModelRoutingDeniedError):
        await route(
            router,
            setup,
            factory(setup[3], setup[4], lambda r: calls.append(r) or GOOD(r)),
        )
    assert calls == []


@pytest.mark.asyncio
async def test_unpriced_candidate_is_skipped_for_priced_one(setup):
    policies = setup[5]
    policies.classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    router, _ = make(setup, priced=("hosted",))
    local_calls = []
    result = await route(
        router,
        setup,
        factory(setup[3], setup[4], lambda r: local_calls.append(r) or GOOD(r)),
        max_attempts=2,
    )
    assert local_calls == []
    assert result.selected.connection_id == setup[4].connection_id
    assert [(e.connection_id, e.reason) for e in result.excluded] == [
        (setup[3].connection_id, "budget_denied")
    ]


@pytest.mark.asyncio
async def test_exhausted_org_limit_denies_with_no_io(setup):
    db = setup[7]
    router, store = make(setup, limit=10)
    calls = []
    with pytest.raises(ModelRoutingDeniedError):
        await route(
            router,
            setup,
            factory(setup[3], setup[4], lambda r: calls.append(r) or GOOD(r)),
        )
    assert calls == []
    assert reservations(db) == []
    summary = store.usage_summary("org", "member", WINDOW)
    assert summary.exposure_micro_usd == 0


@pytest.mark.asyncio
async def test_unknown_usage_stays_ambiguous_and_counted_never_zero(setup):
    db = setup[7]
    router, store = make(setup)
    # reply() carries no usage block: the response is fine but cost is unknown.
    result = await route(router, setup, factory(setup[3], setup[4]))
    attempt = result.selected
    assert result.response.status == "ok"
    assert attempt.cost_known is False
    assert attempt.cost_micro_usd is None
    assert attempt.usage_known is False
    row = reservations(db)[0]
    assert row["state"] == "ambiguous"
    assert row["actual_cost_micro_usd"] is None
    summary = store.usage_summary("org", "member", WINDOW)
    assert summary.unknown_cost_count == 1
    assert summary.ambiguous_exposure_micro_usd == row["reserved_micro_usd"] > 0
    assert summary.known_cost_micro_usd == 0


@pytest.mark.asyncio
async def test_provider_error_response_is_ambiguous_not_released(setup):
    db = setup[7]
    router, store = make(setup)
    result = await route(router, setup, factory(setup[3], setup[4], DOWN))
    assert result.selected.outcome == "error:provider_unavailable"
    assert result.selected.cost_micro_usd is None
    assert not result.selected.cost_known
    assert [r["state"] for r in reservations(db)] == ["ambiguous"]
    assert store.usage_summary("org", "member", WINDOW).unknown_cost_count == 1
    actions = [
        e.action
        for e in store.list_ledger("org", "member", result.selected.reservation_id)
    ]
    assert actions == ["reserve", "settle"]


@pytest.mark.asyncio
async def test_cancellation_mid_attempt_marks_reservation_ambiguous(setup):
    db = setup[7]
    router, store = make(setup)
    started = asyncio.Event()

    async def hang(req):
        started.set()
        await asyncio.Event().wait()

    operation = asyncio.create_task(
        route(router, setup, factory(setup[3], setup[4], hang))
    )
    await started.wait()
    _ = operation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await operation
    assert [r["state"] for r in reservations(db)] == ["ambiguous"]
    assert store.usage_summary("org", "member", WINDOW).ambiguous_exposure_micro_usd > 0
    assert rows(db)[-1]["kind"] == "attempt_cancelled"
    reserved_id = reservations(db)[0]["reservation_id"]
    audit = db.fetchall(
        "SELECT reservation_id FROM model_routing_audit WHERE kind='attempt_cancelled'"
    )
    assert audit[0]["reservation_id"] == reserved_id


@pytest.mark.asyncio
async def test_revocation_mid_attempt_marks_reservation_ambiguous(setup):
    db = setup[7]
    policies = setup[5]
    router, _ = make(setup)

    def revoke(req):
        policies.put(
            "org",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=(), enabled=False),
        )
        return httpx2.Response(200, json=reply())

    with pytest.raises(ModelRoutingDeniedError):
        await route(router, setup, factory(setup[3], setup[4], revoke))
    assert [r["state"] for r in reservations(db)] == ["ambiguous"]
    assert rows(db)[-1]["kind"] == "attempt_denied"


@pytest.mark.asyncio
async def test_unexpected_failure_marks_ambiguous_and_propagates(setup):
    db = setup[7]
    router, _ = make(setup)

    def boom(connection):
        raise RuntimeError("never reaches provider")

    # Failure before reservation: nothing is reserved.
    with pytest.raises(RuntimeError):
        await route(router, setup, boom)
    assert reservations(db) == []

    def broken(req):
        raise ZeroDivisionError

    # An unexpected transport crash after invocation keeps the reserve counted.
    with pytest.raises(ZeroDivisionError):
        await route(router, setup, factory(setup[3], setup[4], broken))
    assert [r["state"] for r in reservations(db)] == ["ambiguous"]


@pytest.mark.asyncio
async def test_failure_after_invocation_is_ambiguous_and_reraised(setup, monkeypatch):
    db = setup[7]
    router, _ = make(setup)

    async def explode(call, client_):
        # Reservation must already be committed when provider I/O would begin.
        assert [r["state"] for r in reservations(db)] == ["reserved"]
        raise OSError("unexpected")

    monkeypatch.setattr(router.admission, "respond_fixture", explode)
    with pytest.raises(OSError, match="unexpected"):
        await route(router, setup, factory(setup[3], setup[4]))
    assert [r["state"] for r in reservations(db)] == ["ambiguous"]
    assert rows(db)[-1]["kind"] == "attempt_failed"


@pytest.mark.asyncio
async def test_failure_before_invocation_releases_reservation(setup, monkeypatch):
    db = setup[7]
    router, store = make(setup)

    def fail_log(*args, **kwargs):
        raise OSError("audit unavailable")

    original = router._log

    def selective(ctx, kind, *args, **kwargs):
        if kind == "attempt_started":
            return fail_log()
        return original(ctx, kind, *args, **kwargs)

    monkeypatch.setattr(router, "_log", selective)
    calls = []
    with pytest.raises(OSError, match="audit unavailable"):
        await route(
            router,
            setup,
            factory(setup[3], setup[4], lambda r: calls.append(r) or GOOD(r)),
        )
    assert calls == []
    assert [r["state"] for r in reservations(db)] == ["released"]
    assert store.usage_summary("org", "member", WINDOW).exposure_micro_usd == 0


@pytest.mark.asyncio
async def test_ambiguous_first_attempt_reduces_fallback_headroom(setup):
    db = setup[7]
    policies = setup[5]
    policies.classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    one = await bound(setup)
    # Room for one reservation plus a sliver: the ambiguous first attempt on the
    # local connection leaves too little for the hosted fallback.
    router, store = make(setup, limit=one + one // 2)
    hosted_calls = []
    result = await route(
        router,
        setup,
        factory(setup[3], setup[4], DOWN, lambda r: hosted_calls.append(r) or GOOD(r)),
        max_attempts=2,
    )
    assert hosted_calls == []
    assert result.exhausted
    assert len(result.attempts) == 1
    assert [(e.connection_id, e.reason) for e in result.excluded] == [
        (setup[4].connection_id, "budget_denied")
    ]
    states = reservations(db)
    assert [r["state"] for r in states] == ["ambiguous"]
    assert states[0]["reserved_micro_usd"] == one
    assert store.usage_summary("org", "member", WINDOW).exposure_micro_usd == one


@pytest.mark.asyncio
async def test_fallback_proceeds_when_org_headroom_allows_both(setup):
    db = setup[7]
    policies = setup[5]
    policies.classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    one = await bound(setup)
    router, _ = make(setup, limit=2 * one + 10)
    result = await route(
        router, setup, factory(setup[3], setup[4], DOWN, GOOD), max_attempts=2
    )
    assert [a.connection_id for a in result.attempts] == [
        setup[3].connection_id,
        setup[4].connection_id,
    ]
    assert result.attempts[0].reservation_id != result.attempts[1].reservation_id
    assert [r["state"] for r in reservations(db)] == ["ambiguous", "ambiguous"]


@pytest.mark.asyncio
async def test_routing_audit_carries_reservation_ids_and_ledger_rows(setup):
    db = setup[7]
    policies = setup[5]
    policies.classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    router, store = make(setup)
    result = await route(
        router, setup, factory(setup[3], setup[4], DOWN, GOOD), max_attempts=2
    )
    audit = db.fetchall(
        "SELECT kind,reservation_id FROM model_routing_audit ORDER BY rowid"
    )
    for attempt in result.attempts:
        mine = [r for r in audit if r["reservation_id"] == attempt.reservation_id]
        assert [r["kind"] for r in mine] == ["attempt_started", "attempt_finished"]
        ledger = store.list_ledger("org", "member", attempt.reservation_id)
        assert [e.action for e in ledger] == ["reserve", "settle"]
        assert ledger[0].reason_code == "reserved_before_io"
    assert all(r["reservation_id"] is None for r in audit if r["kind"] == "excluded")
    text = json.dumps(
        [dict(r) for r in db.fetchall("SELECT * FROM model_routing_audit")]
    )
    for secret in ("evidence-secret", "private@example.test", "objective-secret"):
        assert secret not in text


@pytest.mark.asyncio
async def test_concurrent_routes_cannot_jointly_exceed_budget(setup):
    db = setup[7]
    one = await bound(setup)
    router, store = make(setup, limit=one + one // 2)
    gate = asyncio.Event()
    calls = []

    entered = asyncio.Event()

    async def slow(req):
        calls.append(req)
        entered.set()
        await gate.wait()
        return httpx2.Response(
            200, json=usage_reply(prompt_tokens=10, completion_tokens=5)
        )

    make_client = factory(setup[3], setup[4], slow)
    first = asyncio.create_task(route(router, setup, make_client))
    await entered.wait()
    second = asyncio.create_task(route(router, setup, make_client))
    with pytest.raises(ModelRoutingDeniedError):
        await asyncio.wait_for(second, 5)
    # The in-flight reservation is what blocked the second route.
    assert len(calls) == 1
    gate.set()
    result = await asyncio.wait_for(first, 5)
    assert result.selected.cost_known
    summary = store.usage_summary("org", "member", WINDOW)
    assert summary.exposure_micro_usd <= summary.limit_micro_usd
    assert len(reservations(db)) == 1
    # Settled cost is tiny, so headroom is released for a later route.
    later = await route(router, setup, factory(setup[3], setup[4]))
    assert later.response.status == "ok"


@pytest.mark.asyncio
async def test_gathered_routes_share_one_budget(setup):
    db = setup[7]
    one = await bound(setup)
    router, store = make(setup, limit=one + one // 2)
    results = await asyncio.gather(
        route(router, setup, factory(setup[3], setup[4])),
        route(router, setup, factory(setup[3], setup[4])),
        return_exceptions=True,
    )
    assert sum(isinstance(r, ModelRoutingDeniedError) for r in results) == 1
    assert len(reservations(db)) == 1
    summary = store.usage_summary("org", "member", WINDOW)
    assert not summary.over_limit


def test_constructor_requires_budget_store_on_same_database(setup, tmp_path):
    other = Database(str(tmp_path / "other.db"))
    try:
        with pytest.raises(ModelRoutingDeniedError):
            ModelRoutingService(setup[0], ModelBudgetStore(other))
    finally:
        other.close()
    with pytest.raises(TypeError):
        ModelRoutingService(setup[0])  # pyright: ignore[reportCallIssue]


def test_legacy_audit_table_gains_reservation_column(setup):
    service, db = setup[0], setup[7]
    _ = ModelRoutingService(service, ModelBudgetStore(db, clock=lambda: NOW))
    db.execute("DROP TABLE model_routing_audit")
    db.execute("""CREATE TABLE model_routing_audit (
        audit_id TEXT PRIMARY KEY, route_id TEXT NOT NULL,
        seq INTEGER NOT NULL, org_id TEXT NOT NULL,
        incident_id TEXT NOT NULL, task_id TEXT NOT NULL,
        run_id TEXT NOT NULL, kind TEXT NOT NULL,
        connection_id TEXT, connection_version INTEGER,
        provider TEXT, model TEXT, policy_version INTEGER,
        rationale TEXT, outcome TEXT NOT NULL,
        admission_id TEXT, request_digest TEXT,
        required_capabilities TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    _ = ModelRoutingService(service, ModelBudgetStore(db, clock=lambda: NOW))
    columns = [r["name"] for r in db.fetchall("PRAGMA table_info(model_routing_audit)")]
    assert columns.count("reservation_id") == 1
    # Constructing again is a no-op and the audit stays immutable.
    _ = ModelRoutingService(service, ModelBudgetStore(db, clock=lambda: NOW))
    db.execute(
        "INSERT INTO model_routing_audit(audit_id,route_id,seq,org_id,incident_id,"
        "task_id,run_id,kind,outcome,required_capabilities,created_at)"
        " VALUES('a','r',1,'org','i','t','run','k','o','x','now')"
    )
    with pytest.raises(Exception, match="immutable"):
        db.execute("UPDATE model_routing_audit SET outcome='x'")


@pytest.mark.asyncio
async def test_reconciliation_frees_ambiguous_exposure_for_later_routes(setup):
    one = await bound(setup)
    router, store = make(setup, limit=one + one // 2)
    result = await route(router, setup, factory(setup[3], setup[4], DOWN))
    with pytest.raises(ModelRoutingDeniedError):
        await route(router, setup, factory(setup[3], setup[4]))
    _ = store.reconcile(
        "org",
        "admin",
        result.selected.reservation_id,
        usage=UsageReport(input_tokens=1, output_tokens=1),
        reason_code="provider_invoice",
    )
    again = await route(router, setup, factory(setup[3], setup[4]))
    assert again.response.status == "ok"
