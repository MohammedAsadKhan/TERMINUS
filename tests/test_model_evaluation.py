# ruff: noqa: F811
"""M06: contract-only versus live model coverage (fixture transports only)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import httpx2
import pytest

from terminus.model_gateway.contracts import ModelResponse
from terminus.model_gateway.evaluation import (
    COVERAGE_STATES,
    EvaluationDeniedError,
    EvaluationTask,
    ModelEvaluationService,
    valid_live_transport,
)
from terminus.model_gateway.fixture_client import FixtureModelClient
from terminus.model_gateway.models import ModelConnectionCreate, ModelConnectionUpdate
from terminus.model_gateway.policy import ModelPolicyWrite, PolicyGrant
from terminus.model_gateway.routing import ModelRoutingService, RouteRef
from tests.test_model_admission import NOW, setup  # noqa: F401
from tests.test_model_routing import budget_store

SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class FakeCase:
    case_id: str = "triage-1"
    role: str = "triage"
    title: str = "Fake"
    instructions: str = "do not store"
    evidence: tuple[str, ...] = ("do not store",)
    output_schema: dict = field(default_factory=lambda: dict(SCHEMA))
    required_capabilities: frozenset[str] = frozenset({"structured_output"})
    reasons: tuple[str, ...] | None = None

    def validate_output(self, output):
        if self.reasons is not None:
            return self.reasons
        return () if output.get("verdict") == "benign" else ("verdict_mismatch",)

    def reference_output(self):
        return {"verdict": "benign"}


def make(setup, cases=(FakeCase(),), **kwargs):
    routing = ModelRoutingService(setup[0], budget_store(setup))
    return ModelEvaluationService(
        routing, cases=lambda: tuple(cases), clock=lambda: NOW, **kwargs
    )


def provider(setup):
    return lambda case: EvaluationTask(setup[1], (setup[2].evidence_id,))


def states(records, track=None, connection=None):
    return [
        r.state
        for r in records
        if (track is None or r.track == track)
        and (connection is None or r.connection_id == connection.connection_id)
    ]


@pytest.mark.asyncio
async def test_fixture_pass_is_contract_only_and_live_is_honestly_unavailable(setup):
    local, hosted, db = setup[3], setup[4], setup[7]
    service = make(setup)
    records = await service.run("org", "admin", provider(setup))
    assert states(records, "contract", local) == ["contract_verified"]
    assert states(records, "live", local) == ["transport_unavailable"]
    # Evidence is unclassified (local-only), so the hosted route is denied.
    assert states(records, "contract", hosted) == ["policy_denied"]
    assert states(records, "live", hosted) == ["credentials_missing"]
    assert all(r.state in COVERAGE_STATES for r in records)
    assert not any(r.state == "live_verified" for r in records)
    passed = next(r for r in records if r.state == "contract_verified")
    assert passed.fixture_only is True
    assert passed.cost_known is False
    assert passed.cost_micro_usd is None
    assert passed.reservation_id is not None
    # Went through admission, budget reservation and routing audit.
    assert len(db.fetchall("SELECT 1 FROM model_reservations")) == 1
    assert db.fetchall("SELECT outcome FROM model_admission_audit")
    assert db.fetchall("SELECT kind FROM model_routing_audit")
    denied = next(r for r in records if r.state == "policy_denied")
    assert "admission_denied" in denied.failure_reasons
    summary = service.coverage_summary("org", "member")
    assert summary.live_verified_count == 0
    assert summary.contract_verified_count == 1
    assert summary.demo_ready is False


@pytest.mark.asyncio
@pytest.mark.parametrize("provider_name", ["anthropic", "gemini", "openrouter"])
async def test_each_provider_shape_round_trips_the_codec(setup, provider_name):
    created = setup[0].connections.create(
        "org",
        "admin",
        ModelConnectionCreate(
            name=f"P {provider_name}",
            provider=provider_name,
            models=["fixture-model"],
            enabled=True,
        ),
    )
    policies = setup[5]
    current = policies.get("org", "admin")
    grants = (
        *current.grants,
        PolicyGrant(
            role="triage",
            connection_id=created.connection_id,
            connection_version=1,
            models=("fixture-model",),
            classifications=("local_only", "approved_cloud", "redacted_cloud"),
        ),
    )
    policies.put(
        "org",
        "admin",
        ModelPolicyWrite(expected_version=current.version, grants=grants),
    )
    policies.classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    service = make(setup)
    _ = service.routing.budgets.put_price(
        "org",
        "admin",
        created.connection_id,
        "fixture-model",
        input_per_mtok_micro_usd=1_000_000,
        output_per_mtok_micro_usd=2_000_000,
    )
    records = await service.run("org", "admin", provider(setup))
    mine = [r for r in records if r.connection_id == created.connection_id]
    assert states(mine, "contract") == ["contract_verified"]
    assert states(mine, "live") == ["credentials_missing"]


@pytest.mark.asyncio
async def test_mismatching_output_is_contract_failed_with_reasons(setup):
    service = make(setup, fixture_output=lambda case, conn: {"verdict": "malicious"})
    records = await service.run("org", "admin", provider(setup))
    row = next(r for r in records if r.track == "contract" and r.provider == "local")
    assert row.state == "contract_failed"
    assert row.failure_reasons == ("verdict_mismatch",)
    assert service.coverage_summary("org", "admin").contract_verified_count == 0


@pytest.mark.asyncio
async def test_schema_violation_in_fixture_is_contract_failed(setup):
    service = make(setup, fixture_output=lambda case, conn: {"unexpected": "x"})
    records = await service.run("org", "admin", provider(setup))
    row = next(r for r in records if r.track == "contract" and r.provider == "local")
    assert row.state == "contract_failed"
    assert row.failure_reasons == ("response:invalid_provider_contract",)


@pytest.mark.asyncio
async def test_reasons_are_bounded_and_scrubbed(setup):
    noisy = ("x" * 500, "api_key=abcdefghijklmnop", "sk-abcdefghijkl", *["r"] * 20)
    service = make(setup, cases=(FakeCase(reasons=noisy),))
    records = await service.run("org", "admin", provider(setup))
    row = next(r for r in records if r.state == "contract_failed")
    assert len(row.failure_reasons) <= 8
    assert all(len(item) <= 120 for item in row.failure_reasons)
    assert "abcdefghijkl" not in " ".join(row.failure_reasons)


@pytest.mark.asyncio
async def test_capability_unsupported_and_not_configured_states(setup):
    service = make(
        setup, cases=(FakeCase(required_capabilities=frozenset({"tool_calls"})),)
    )
    records = await service.run("org", "admin", provider(setup))
    assert set(states(records)) == {"capability_unsupported"}
    assert setup[7].fetchall("SELECT 1 FROM model_reservations") == []

    service = make(setup)
    records = await service.run("org", "admin")  # no evaluation task harness
    assert set(states(records)) == {"not_configured"}
    assert records[0].failure_reasons == ("no_evaluation_task",)

    records = await service.run("org", "admin", lambda case: None)
    assert set(states(records)) == {"not_configured"}

    service = make(setup, cases=(FakeCase(role="response_planner"),))
    records = await service.run("org", "admin", provider(setup))
    assert records[0].failure_reasons == ("task_role_mismatch",)


@pytest.mark.asyncio
async def test_disabled_connection_is_not_configured(setup):
    local = setup[3]
    _ = setup[0].connections.update(
        "org",
        "admin",
        local.connection_id,
        ModelConnectionUpdate(expected_version=1, enabled=False),
    )
    service = make(setup)
    records = await service.run("org", "admin", provider(setup))
    assert states(records, connection=local) == ["not_configured"] * 2


@pytest.mark.asyncio
async def test_policy_denial_when_grants_are_revoked(setup):
    _ = setup[5].put("org", "admin", ModelPolicyWrite(expected_version=1, grants=()))
    service = make(setup)
    records = await service.run("org", "admin", provider(setup))
    assert set(states(records, "contract")) == {"policy_denied"}
    assert set(states(records, "live")) == {
        "transport_unavailable",
        "credentials_missing",
    }
    assert setup[7].fetchall("SELECT 1 FROM model_reservations") == []


@pytest.mark.asyncio
async def test_run_requires_admin(setup):
    service = make(setup)
    for actor in ("member", "viewer", "nobody"):
        with pytest.raises(EvaluationDeniedError):
            await service.run("org", actor, provider(setup))
    assert service.coverage_summary("org", "viewer").live_verified_count == 0


@pytest.mark.asyncio
async def test_rerun_is_append_only_new_run(setup):
    db = setup[7]
    service = make(setup)
    first = await service.run("org", "admin", provider(setup))
    before = db.fetchall("SELECT * FROM model_evaluation_records ORDER BY seq")
    second = await service.run("org", "admin", provider(setup))
    assert {r.run_id for r in first}.isdisjoint({r.run_id for r in second})
    after = db.fetchall("SELECT * FROM model_evaluation_records ORDER BY seq")
    assert after[: len(before)] == before
    assert len(after) == 2 * len(before)
    assert len({r["record_id"] for r in after}) == len(after)
    # Coverage reflects the latest run only, not accumulated history.
    assert service.coverage_summary("org", "admin").contract_verified_count == 1
    listed = service.list_records("org", "admin", run_id=second[0].run_id)
    assert len(listed) == len(second)


@pytest.mark.asyncio
async def test_records_are_immutable(setup):
    db = setup[7]
    service = make(setup)
    _ = await service.run("org", "admin", provider(setup))
    with pytest.raises(Exception, match="immutable"):
        db.execute("UPDATE model_evaluation_records SET state='live_verified'")
    with pytest.raises(Exception, match="immutable"):
        db.execute("DELETE FROM model_evaluation_records")
    # Even a direct insert cannot label a fixture row as live.
    with pytest.raises(Exception, match=r"(?i)constraint"):
        db.execute(
            "INSERT INTO model_evaluation_records(record_id,run_id,org_id,"
            "actor_user_id,connection_id,connection_version,provider,model,case_id,"
            "role,track,state,fixture_only,failure_reasons,cost_known,policy_version,"
            "started_at,finished_at) VALUES('r','r','org','a','c',1,'local','m','c',"
            "'r','live','live_verified',1,'[]',0,0,'t','t')"
        )


@pytest.mark.asyncio
async def test_no_secrets_prompts_or_endpoints_are_stored(setup):
    db = setup[7]
    service = make(setup)
    _ = await service.run("org", "admin", provider(setup))
    text = json.dumps(
        [dict(r) for r in db.fetchall("SELECT * FROM model_evaluation_records")]
    )
    for forbidden in (
        "evidence-secret",
        "private@example.test",
        "objective-secret",
        "do not store",
        "models.corp.test",
        "https://",
        "fixture-key-not-a-credential",
    ):
        assert forbidden not in text


@pytest.mark.asyncio
async def test_tenant_isolation(setup):
    db = setup[7]
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("other", "Other", NOW.isoformat()),
    )
    db.execute(
        "INSERT INTO users VALUES('o2','o2@example.test','h','o2',?)",
        (NOW.isoformat(),),
    )
    db.execute("INSERT INTO memberships VALUES('other','o2','admin')")
    service = make(setup)
    _ = await service.run("org", "admin", provider(setup))
    assert service.coverage_summary("other", "o2").pairs == ()
    assert service.list_records("other", "o2") == ()
    with pytest.raises(EvaluationDeniedError):
        service.coverage_summary("org", "o2")
    with pytest.raises(EvaluationDeniedError):
        service.list_records("org", "o2")
    with pytest.raises(EvaluationDeniedError):
        await service.run("org", "o2", provider(setup))
    assert service.coverage_summary("org", "admin").pairs


@pytest.mark.asyncio
async def test_live_verified_is_unreachable_with_fixture_or_fake_transports(setup):
    local = setup[3]

    def fixture_as_live(connection):
        return FixtureModelClient(
            connection.provider,
            httpx2.MockTransport(lambda r: httpx2.Response(200, json={})),
            base_url=connection.base_url,
        )

    class Imposter:
        is_live_transport = True
        fixture_only = True

        async def respond(self, request):
            raise AssertionError("must never be called")

    class Unmarked:
        async def respond(self, request):
            raise AssertionError("must never be called")

    assert not valid_live_transport(fixture_as_live(local))
    assert not valid_live_transport(Imposter())
    assert not valid_live_transport(Unmarked())
    service = make(setup)
    for factory in (fixture_as_live, lambda c: Imposter(), lambda c: Unmarked()):
        records = await service.run(
            "org", "admin", provider(setup), live_transports=factory
        )
        live = [
            r
            for r in records
            if r.track == "live" and r.connection_id == local.connection_id
        ]
        assert [r.state for r in live] == ["transport_unavailable"]
        assert live[0].failure_reasons == ("live_transport_rejected",)
        assert not any(r.state == "live_verified" for r in records)
    ref = RouteRef(connection_id=local.connection_id, model="fixture-model")
    summary = service.coverage_summary("org", "admin", demo_model=ref)
    assert summary.live_verified_count == 0
    assert summary.demo_ready is False
    assert summary.demo_missing_live_case_ids == ("triage-1",)


@pytest.mark.asyncio
async def test_demo_ready_false_without_demo_model_or_cases(setup):
    service = make(setup)
    _ = await service.run("org", "admin", provider(setup))
    ref = RouteRef(connection_id=setup[3].connection_id, model="fixture-model")
    assert service.coverage_summary("org", "admin").demo_ready is False
    assert service.coverage_summary("org", "admin", demo_model=ref).demo_ready is False
    # An empty requirement never passes vacuously.
    empty = service.coverage_summary(
        "org", "admin", demo_model=ref, demo_case_ids=frozenset()
    )
    assert empty.demo_ready is False


@pytest.mark.asyncio
async def test_self_declared_live_transport_cannot_fabricate_live_coverage(setup):
    """A boolean marker cannot bypass admission or manufacture live evidence."""
    local = setup[3]
    calls = []

    class GenuineLive:
        is_live_transport = True

        async def respond(self, request):
            calls.append(request)
            return ModelResponse(
                status="ok", model="fixture-model", output={"verdict": "benign"}
            )

    assert not valid_live_transport(GenuineLive())
    service = make(setup)
    records = await service.run(
        "org", "admin", provider(setup), live_transports=lambda c: GenuineLive()
    )
    live = next(
        r
        for r in records
        if r.track == "live" and r.connection_id == local.connection_id
    )
    assert live.state == "transport_unavailable"
    assert calls == []
    # Hosted without a configured credential can never be live.
    hosted_live = next(
        r
        for r in records
        if r.track == "live" and r.connection_id == setup[4].connection_id
    )
    assert hosted_live.state == "credentials_missing"
    ref = RouteRef(connection_id=local.connection_id, model="fixture-model")
    summary = service.coverage_summary("org", "admin", demo_model=ref)
    assert summary.live_verified_count == 0
    assert summary.demo_ready is False
    # Contract passes are separate and never counted as live.
    assert summary.contract_verified_count == 1
    # A later non-live run supersedes it: coverage follows the latest record.
    _ = await service.run("org", "admin", provider(setup))
    again = service.coverage_summary("org", "admin", demo_model=ref)
    assert again.live_verified_count == 0
    assert again.demo_ready is False


@pytest.mark.asyncio
async def test_real_case_suite_reference_outputs_pass_contract_track(setup):
    from terminus.model_gateway.evaluation_cases import all_cases

    local = setup[3]
    triage = tuple(c for c in all_cases() if c.role == "triage")
    assert len(triage) >= 2
    service = make(setup, cases=triage)
    records = await service.run("org", "admin", provider(setup))
    contract = states(records, "contract", local)
    assert contract == ["contract_verified"] * len(triage)
    assert not any(r.state == "live_verified" for r in records)
    assert service.coverage_summary("org", "member").demo_ready is False
