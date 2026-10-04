"""M05: atomic reservations, durable usage ledger and reconciliation."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import pytest

from terminus.model_gateway.ledger import (
    BudgetConflictError,
    BudgetDeniedError,
    BudgetExceededError,
    BudgetNotFoundError,
    BudgetValidationError,
    ModelBudgetStore,
    ReservationRequest,
    UsageReport,
    window_key_for,
)
from terminus.storage.db import Database

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
WINDOW = window_key_for(NOW)
MODEL = "model-a"


@pytest.fixture
def env(tmp_path):
    path = str(tmp_path / "ledger.db")
    db = Database(path)
    for org in ("org", "other"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, NOW.isoformat()),
        )
    for actor, org, role in (
        ("admin", "org", "admin"),
        ("member", "org", "member"),
        ("viewer", "org", "viewer"),
        ("outsider", "other", "admin"),
    ):
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (actor, f"{actor}@example.test", "hash", actor, NOW.isoformat()),
        )
        db.execute("INSERT INTO memberships VALUES(?,?,?)", (org, actor, role))
    store = ModelBudgetStore(db, clock=lambda: NOW)
    # $1/Mtok input, $2/Mtok output, cached $0.25, reasoning $4 => micro-USD.
    for connection in ("conn-1", "conn-2"):
        _ = store.put_price(
            "org",
            "admin",
            connection,
            MODEL,
            input_per_mtok_micro_usd=1_000_000,
            output_per_mtok_micro_usd=2_000_000,
            cached_input_per_mtok_micro_usd=250_000,
            reasoning_per_mtok_micro_usd=4_000_000,
        )
    _ = store.put_budget("org", "admin", WINDOW, limit_micro_usd=1_000_000)
    return db, store, path


def req(
    key: str = "k1",
    connection: str = "conn-1",
    *,
    request_bytes: int = 1000,
    max_output: int = 1000,
    **extra,
) -> ReservationRequest:
    return ReservationRequest(
        idempotency_key=key,
        incident_id="inc",
        task_id="task",
        run_id="run",
        connection_id=connection,
        connection_version=1,
        model=MODEL,
        request_bytes=request_bytes,
        max_output_tokens=max_output,
        **extra,
    )


# Reserve bound for req() defaults: 1000*4 (max rate in=1e6) -> input at 1e6,
# output at max(2e6, 4e6)=4e6: (1000*1e6 + 1000*4e6)/1e6 = 5000 micro-USD.
BOUND = 5000


def test_reserve_computes_conservative_bound(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    assert res.state == "reserved"
    assert res.reserved_micro_usd == BOUND
    assert res.reserved_tokens == 2000
    assert res.window_key == WINDOW


def test_explicit_input_bound_overrides_bytes(env):
    _, store, _ = env
    res = store.reserve("org", "admin", req(request_bytes=10_000, max_input_tokens=10))
    assert res.reserved_tokens == 1010


def test_reserve_writes_ledger_row_first(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    entries = store.list_ledger("org", "member", res.reservation_id)
    assert [e.action for e in entries] == ["reserve"]
    assert entries[0].cost_known is False
    assert entries[0].cost_micro_usd is None


def test_idempotent_reserve_returns_same(env):
    _, store, _ = env
    first = store.reserve("org", "member", req())
    again = store.reserve("org", "member", req())
    assert again.reservation_id == first.reservation_id
    assert store.usage_summary("org", "member").reserved_exposure_micro_usd == BOUND


def test_idempotency_key_with_different_parameters_conflicts(env):
    _, store, _ = env
    _ = store.reserve("org", "member", req())
    with pytest.raises(BudgetConflictError):
        _ = store.reserve("org", "member", req(max_output=999))
    with pytest.raises(BudgetConflictError):
        _ = store.reserve("org", "member", req(connection="conn-2"))


def test_unpriced_model_denied(env):
    _, store, _ = env
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req(connection="conn-unpriced"))


def test_missing_budget_denied(env):
    db, _, _ = env
    store = ModelBudgetStore(db, clock=lambda: NOW + timedelta(days=1))
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req())


def test_over_limit_denied_with_safe_error(env):
    _, store, _ = env
    with pytest.raises(BudgetExceededError) as info:
        _ = store.reserve("org", "member", req(max_output=1_000_000))
    assert "conn-1" not in str(info.value)
    assert store.usage_summary("org", "member").exposure_micro_usd == 0


def test_token_limit_enforced(env):
    _, store, _ = env
    _ = store.put_budget(
        "org",
        "admin",
        WINDOW,
        limit_micro_usd=1_000_000,
        limit_tokens=2500,
        expected_version=1,
    )
    _ = store.reserve("org", "member", req("a"))
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req("b"))


def test_concurrent_reserves_never_exceed_limit(env):
    _, store, path = env
    # Limit fits exactly 10 reservations of BOUND.
    _ = store.put_budget(
        "org", "admin", WINDOW, limit_micro_usd=BOUND * 10, expected_version=1
    )
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(30)

    def work(index: int) -> None:
        local = ModelBudgetStore(Database(path), clock=lambda: NOW)
        barrier.wait()
        try:
            _ = local.reserve(
                "org", "member", req(f"k{index}", f"conn-{index % 2 + 1}")
            )
            result = "ok"
        except BudgetExceededError:
            result = "denied"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(30)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("ok") == 10
    assert outcomes.count("denied") == 20
    assert store.usage_summary("org", "member").exposure_micro_usd == BOUND * 10


def test_fallback_connections_share_org_limit(env):
    _, store, _ = env
    _ = store.put_budget(
        "org", "admin", WINDOW, limit_micro_usd=BOUND * 2, expected_version=1
    )
    _ = store.reserve("org", "member", req("a", "conn-1"))
    _ = store.reserve("org", "member", req("a-fallback", "conn-2"))
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req("a-retry", "conn-1"))
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req("a-fallback-2", "conn-2"))


def test_settle_computes_known_cost(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    done = store.settle(
        "org",
        res.reservation_id,
        UsageReport(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=0,
            reasoning_tokens=0,
        ),
    )
    assert done.state == "settled"
    # 100*1 + 50*2 = 200 micro-USD
    assert done.actual_cost_micro_usd == 200
    summary = store.usage_summary("org", "member")
    assert summary.known_cost_micro_usd == 200
    assert summary.exposure_micro_usd == 200
    assert summary.unknown_cost_count == 0


def test_cached_and_reasoning_tokens_priced_separately(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    done = store.settle(
        "org",
        res.reservation_id,
        UsageReport(
            input_tokens=1000,
            output_tokens=500,
            cached_input_tokens=600,
            reasoning_tokens=200,
        ),
    )
    # 400*1 + 600*0.25 + 300*2 + 200*4 = 400+150+600+800
    assert done.actual_cost_micro_usd == 1950


def test_missing_cached_count_unknown_when_priced_differently(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    done = store.settle(
        "org", res.reservation_id, UsageReport(input_tokens=10, output_tokens=10)
    )
    assert done.state == "ambiguous"
    assert done.actual_cost_micro_usd is None


def test_missing_cached_count_ok_when_price_equal(env):
    _, store, _ = env
    _ = store.put_price(
        "org",
        "admin",
        "plain",
        MODEL,
        input_per_mtok_micro_usd=1_000_000,
        output_per_mtok_micro_usd=2_000_000,
    )
    res = store.reserve("org", "member", req("p", "plain"))
    done = store.settle(
        "org", res.reservation_id, UsageReport(input_tokens=10, output_tokens=10)
    )
    assert done.state == "settled"
    assert done.actual_cost_micro_usd == 30


def test_unknown_usage_is_ambiguous_and_counted_never_zero(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    done = store.settle("org", res.reservation_id, UsageReport())
    assert done.state == "ambiguous"
    summary = store.usage_summary("org", "member")
    assert summary.unknown_cost_count == 1
    assert summary.ambiguous_exposure_micro_usd == BOUND
    assert summary.known_cost_micro_usd == 0
    assert summary.exposure_micro_usd == BOUND
    entry = store.list_ledger("org", "member", res.reservation_id)[-1]
    assert entry.cost_known is False
    assert entry.cost_micro_usd is None


def test_inconsistent_usage_is_unknown(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    done = store.settle(
        "org",
        res.reservation_id,
        UsageReport(
            input_tokens=5, output_tokens=5, cached_input_tokens=9, reasoning_tokens=0
        ),
    )
    assert done.state == "ambiguous"


def test_ambiguous_exposure_blocks_new_reserves(env):
    _, store, _ = env
    _ = store.put_budget(
        "org", "admin", WINDOW, limit_micro_usd=BOUND, expected_version=1
    )
    res = store.reserve("org", "member", req("a"))
    _ = store.mark_ambiguous("org", res.reservation_id, reason_code="timeout")
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req("b"))


def test_actual_cost_above_reserve_recorded_and_blocks_later(env):
    _, store, _ = env
    _ = store.put_budget(
        "org", "admin", WINDOW, limit_micro_usd=BOUND, expected_version=1
    )
    res = store.reserve("org", "member", req("a", max_output=10, request_bytes=10))
    done = store.settle(
        "org",
        res.reservation_id,
        UsageReport(
            input_tokens=1000,
            output_tokens=1000,
            cached_input_tokens=0,
            reasoning_tokens=1000,
        ),
    )
    assert done.actual_cost_micro_usd is not None
    assert done.actual_cost_micro_usd > res.reserved_micro_usd
    summary = store.usage_summary("org", "member")
    assert summary.exposure_micro_usd == done.actual_cost_micro_usd
    assert summary.over_limit is (summary.exposure_micro_usd > BOUND)
    with pytest.raises(BudgetExceededError):
        _ = store.reserve("org", "member", req("b", max_output=1, request_bytes=1))


def test_settle_idempotent_and_conflicting_usage(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    usage = UsageReport(
        input_tokens=10, output_tokens=10, cached_input_tokens=0, reasoning_tokens=0
    )
    first = store.settle("org", res.reservation_id, usage)
    second = store.settle("org", res.reservation_id, usage)
    assert first == second
    assert len(store.list_ledger("org", "member", res.reservation_id)) == 2
    with pytest.raises(BudgetConflictError):
        _ = store.settle(
            "org",
            res.reservation_id,
            UsageReport(
                input_tokens=99,
                output_tokens=1,
                cached_input_tokens=0,
                reasoning_tokens=0,
            ),
        )


def test_settle_uses_price_snapshot_not_current_price(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.put_price(
        "org",
        "admin",
        "conn-1",
        MODEL,
        input_per_mtok_micro_usd=9_000_000,
        output_per_mtok_micro_usd=9_000_000,
        expected_version=1,
    )
    done = store.settle(
        "org",
        res.reservation_id,
        UsageReport(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=0,
            reasoning_tokens=0,
        ),
    )
    assert done.actual_cost_micro_usd == 200


def test_release_only_before_io(env):
    _, store, _ = env
    a = store.reserve("org", "member", req("a"))
    released = store.release("org", a.reservation_id)
    assert released.state == "released"
    assert store.release("org", a.reservation_id).state == "released"
    assert store.usage_summary("org", "member").exposure_micro_usd == 0
    b = store.reserve("org", "member", req("b"))
    _ = store.mark_ambiguous("org", b.reservation_id)
    with pytest.raises(BudgetConflictError):
        _ = store.release("org", b.reservation_id)
    c = store.reserve("org", "member", req("c"))
    _ = store.settle("org", c.reservation_id, UsageReport())
    with pytest.raises(BudgetConflictError):
        _ = store.release("org", c.reservation_id)


def test_settle_after_release_conflicts(env):
    _, store, _ = env
    a = store.reserve("org", "member", req("a"))
    _ = store.release("org", a.reservation_id)
    with pytest.raises(BudgetConflictError):
        _ = store.settle(
            "org", a.reservation_id, UsageReport(input_tokens=1, output_tokens=1)
        )


def test_mark_ambiguous_idempotent(env):
    _, store, _ = env
    a = store.reserve("org", "member", req("a"))
    one = store.mark_ambiguous("org", a.reservation_id, reason_code="cancelled")
    two = store.mark_ambiguous("org", a.reservation_id, reason_code="cancelled")
    assert one.state == two.state == "ambiguous"
    assert len(store.list_ledger("org", "member", a.reservation_id)) == 2


def test_stale_recovery_marks_ambiguous_never_releases(env):
    db, store, _ = env
    old = store.reserve("org", "member", req("old"))
    later = ModelBudgetStore(db, clock=lambda: NOW + timedelta(hours=2))
    fresh = later.reserve("org", "member", req("fresh"))
    count = later.recover_stale("org", NOW + timedelta(hours=1))
    assert count == 1
    assert (
        later.get_reservation("org", "member", old.reservation_id).state == "ambiguous"
    )
    assert (
        later.get_reservation("org", "member", fresh.reservation_id).state == "reserved"
    )
    assert later.recover_stale("org", NOW + timedelta(hours=1)) == 0
    assert (
        later.usage_summary("org", "member", WINDOW).ambiguous_exposure_micro_usd
        == BOUND
    )


def test_reconcile_with_usage(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.settle("org", res.reservation_id, UsageReport())
    done = store.reconcile(
        "org",
        "admin",
        res.reservation_id,
        usage=UsageReport(
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=0,
            reasoning_tokens=0,
        ),
        reason_code="provider_invoice",
    )
    assert done.state == "reconciled"
    assert done.actual_cost_micro_usd == 200
    summary = store.usage_summary("org", "member")
    assert summary.known_cost_micro_usd == 200
    assert summary.unknown_cost_count == 0
    assert summary.exposure_micro_usd == 200


def test_reconcile_confirmed_no_charge(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.mark_ambiguous("org", res.reservation_id)
    done = store.reconcile(
        "org",
        "admin",
        res.reservation_id,
        confirmed_no_charge=True,
        reason_code="provider_confirmed",
    )
    assert done.actual_cost_micro_usd == 0
    entry = store.list_ledger("org", "admin", res.reservation_id)[-1]
    assert entry.cost_known is True
    assert entry.cost_micro_usd == 0
    assert entry.actor_user_id == "admin"


def test_reconcile_never_silently_zero(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.mark_ambiguous("org", res.reservation_id)
    for kwargs in (
        {},
        {"usage": UsageReport(), "confirmed_no_charge": True},
        {"usage": UsageReport(input_tokens=1)},
        {"usage": UsageReport()},
    ):
        with pytest.raises(BudgetValidationError):
            _ = store.reconcile(
                "org", "admin", res.reservation_id, reason_code="x_evidence", **kwargs
            )
    assert (
        store.get_reservation("org", "admin", res.reservation_id).state == "ambiguous"
    )


def test_reconcile_admin_only_and_tenant_scoped(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.mark_ambiguous("org", res.reservation_id)
    for actor in ("member", "viewer", "outsider", "nobody"):
        with pytest.raises(BudgetDeniedError):
            _ = store.reconcile(
                "org",
                actor,
                res.reservation_id,
                confirmed_no_charge=True,
                reason_code="evidence",
            )
    with pytest.raises(BudgetDeniedError):
        _ = store.reconcile(
            "other",
            "admin",
            res.reservation_id,
            confirmed_no_charge=True,
            reason_code="evidence",
        )
    with pytest.raises(BudgetNotFoundError):
        _ = store.reconcile(
            "other",
            "outsider",
            res.reservation_id,
            confirmed_no_charge=True,
            reason_code="evidence",
        )


def test_reconcile_requires_ambiguous(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    with pytest.raises(BudgetConflictError):
        _ = store.reconcile(
            "org",
            "admin",
            res.reservation_id,
            confirmed_no_charge=True,
            reason_code="evidence",
        )


def test_tenant_isolation_on_system_transitions_and_reads(env):
    _, store, _ = env
    res = store.reserve("org", "member", req())
    with pytest.raises(BudgetNotFoundError):
        _ = store.settle("other", res.reservation_id, UsageReport())
    with pytest.raises(BudgetNotFoundError):
        _ = store.release("other", res.reservation_id)
    with pytest.raises(BudgetNotFoundError):
        _ = store.mark_ambiguous("other", res.reservation_id)
    with pytest.raises(BudgetNotFoundError):
        _ = store.get_reservation("other", "outsider", res.reservation_id)
    with pytest.raises(BudgetDeniedError):
        _ = store.get_reservation("org", "outsider", res.reservation_id)
    assert store.list_ledger("other", "outsider") == ()
    with pytest.raises(BudgetDeniedError):
        _ = store.usage_summary("org", "outsider")


def test_authorization_levels(env):
    _, store, _ = env
    with pytest.raises(BudgetDeniedError):
        _ = store.reserve("org", "viewer", req())
    with pytest.raises(BudgetDeniedError):
        _ = store.reserve("org", "outsider", req())
    with pytest.raises(BudgetDeniedError):
        _ = store.reserve("other", "member", req())
    assert store.usage_summary("org", "viewer").org_id == "org"
    assert store.get_price("org", "member", "conn-1", MODEL).version == 1


def test_price_and_budget_writes_admin_only_with_cas(env):
    _, store, _ = env
    with pytest.raises(BudgetDeniedError):
        _ = store.put_price(
            "org",
            "member",
            "c",
            MODEL,
            input_per_mtok_micro_usd=1,
            output_per_mtok_micro_usd=1,
        )
    with pytest.raises(BudgetDeniedError):
        _ = store.put_budget(
            "org", "member", WINDOW, limit_micro_usd=1, expected_version=1
        )
    with pytest.raises(BudgetConflictError):
        _ = store.put_budget(
            "org", "admin", WINDOW, limit_micro_usd=1, expected_version=0
        )
    with pytest.raises(BudgetConflictError):
        _ = store.put_price(
            "org",
            "admin",
            "conn-1",
            MODEL,
            input_per_mtok_micro_usd=1,
            output_per_mtok_micro_usd=1,
        )
    with pytest.raises(BudgetValidationError):
        _ = store.put_budget("org", "admin", "not-a-date", limit_micro_usd=1)
    with pytest.raises(BudgetValidationError):
        _ = store.put_budget("org", "admin", "2026-13-45", limit_micro_usd=1)
    with pytest.raises(BudgetValidationError):
        _ = store.put_budget("org", "admin", "2026-10-05", limit_micro_usd=-1)


def test_prices_isolated_per_org(env):
    _, store, _ = env
    with pytest.raises(BudgetNotFoundError):
        _ = store.get_price("other", "outsider", "conn-1", MODEL)


def test_ledger_is_immutable(env):
    db, store, _ = env
    _ = store.reserve("org", "member", req())
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        _ = db.execute("UPDATE model_usage_ledger SET cost_micro_usd = 0")
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        _ = db.execute("DELETE FROM model_usage_ledger")
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        _ = db.execute("UPDATE model_budget_audit SET action = 'put_price'")


def test_ledger_rejects_unknown_cost_stored_as_zero(env):
    db, store, _ = env
    res = store.reserve("org", "member", req())
    with pytest.raises(sqlite3.IntegrityError):
        _ = db.execute(
            """INSERT INTO model_usage_ledger
               (org_id, reservation_id, action, to_state, window_key, connection_id,
                model, reserved_micro_usd, cost_known, cost_micro_usd, reason_code,
                created_at)
               VALUES ('org', ?, 'settle', 'ambiguous', ?, 'c', 'm', 1, 0, 0, 'x', 't')""",
            (res.reservation_id, WINDOW),
        )


def test_restart_durability(env):
    _db, store, path = env
    res = store.reserve("org", "member", req())
    _ = store.settle("org", res.reservation_id, UsageReport())
    restarted = ModelBudgetStore(Database(path), clock=lambda: NOW)
    again = restarted.get_reservation("org", "member", res.reservation_id)
    assert again.state == "ambiguous"
    summary = restarted.usage_summary("org", "member")
    assert summary.ambiguous_exposure_micro_usd == BOUND
    assert (
        restarted.reserve("org", "member", req()).reservation_id == res.reservation_id
    )
    assert [e.action for e in restarted.list_ledger("org", "member")] == [
        "reserve",
        "settle",
    ]


def test_no_secrets_in_ledger_rows(env):
    db, store, _ = env
    res = store.reserve("org", "member", req())
    _ = store.settle(
        "org", res.reservation_id, UsageReport(input_tokens=1, output_tokens=1)
    )
    rows = db.fetchall("SELECT * FROM model_usage_ledger")
    flat = " ".join(str(v) for row in rows for v in row.values()).lower()
    for needle in ("secret", "password", "http", "bearer", "sk-", "prompt"):
        assert needle not in flat
    with pytest.raises(BudgetValidationError):
        _ = store.release(
            "org", res.reservation_id, reason_code="https://evil/secret?k=1"
        )


def test_invalid_requests_rejected_safely(env):
    _, store, _ = env
    with pytest.raises(BudgetValidationError):
        _ = store.settle("org", "x", UsageReport(), reason_code="Bad Reason!")
    with pytest.raises(BudgetNotFoundError):
        _ = store.settle("org", "missing", UsageReport())
    with pytest.raises(BudgetValidationError):
        _ = store.recover_stale("org", datetime(2026, 1, 1))  # noqa: DTZ001
    with pytest.raises(BudgetValidationError):
        _ = store.list_ledger("org", "member", limit=0)


def test_summary_other_window_and_remaining(env):
    _, store, _ = env
    _ = store.reserve("org", "member", req())
    summary = store.usage_summary("org", "member")
    assert summary.remaining_micro_usd == 1_000_000 - BOUND
    assert summary.over_limit is False
    empty = store.usage_summary("org", "member", "2026-01-01")
    assert empty.limit_micro_usd is None
    assert empty.remaining_micro_usd is None
    assert empty.exposure_micro_usd == 0
