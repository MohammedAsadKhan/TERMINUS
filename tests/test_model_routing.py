# ruff: noqa: F811, RUF059
"""M04: capability routing and bounded approved fallback (fixture transports only)."""

from __future__ import annotations

import json

import httpx2
import pytest

from terminus.model_gateway.models import ModelConnectionCreate, ModelConnectionUpdate
from terminus.model_gateway.policy import ModelPolicyWrite, PolicyGrant
from terminus.model_gateway.routing import (
    ModelRoutingDeniedError,
    ModelRoutingService,
    RouteRef,
)
from tests.test_model_admission import client, reply, setup  # noqa: F401

DOWN = lambda req: httpx2.Response(503)  # noqa: E731
GOOD = lambda req: httpx2.Response(200, json=reply())  # noqa: E731


def factory(local, hosted, local_cb=GOOD, hosted_cb=GOOD):
    def make(connection):
        if connection.connection_id == local.connection_id:
            return client(local, local_cb)
        if connection.connection_id == hosted.connection_id:
            return client(hosted, hosted_cb)
        return None

    return make


def router(fixture):
    return ModelRoutingService(fixture[0])


def rows(db):
    return db.fetchall(
        "SELECT kind,outcome,rationale,connection_id,model FROM model_routing_audit ORDER BY rowid"
    )


@pytest.mark.asyncio
async def test_policy_order_route_records_model_rationale_and_provenance(setup):
    service, lease, evidence, local, hosted, _, _, db = setup
    seen = []
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted, hosted_cb=lambda r: seen.append(r) or GOOD(r)),
    )
    assert result.response.status == "ok"
    assert result.selected.connection_id == local.connection_id
    assert result.selected.model == "fixture-model"
    assert result.selected.rationale == "policy_order"
    assert result.selected.policy_version == 1
    assert not result.exhausted
    assert seen == []
    assert [r["kind"] for r in rows(db)] == ["attempt_started", "attempt_finished"]


@pytest.mark.asyncio
async def test_fallback_is_off_by_default_and_never_scripted(setup):
    service, lease, evidence, local, hosted, policies, _, db = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    hosted_calls = []
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted, DOWN, lambda r: hosted_calls.append(r) or GOOD(r)),
    )
    assert result.response.status == "error"
    assert result.exhausted
    assert len(result.attempts) == 1
    assert result.selected.outcome == "error:provider_unavailable"
    assert result.response.output is None
    assert hosted_calls == []


@pytest.mark.asyncio
async def test_bounded_fallback_reauthorizes_each_attempt(setup):
    service, lease, evidence, local, hosted, policies, _, db = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted, DOWN, GOOD),
        max_attempts=2,
    )
    assert result.response.status == "ok"
    assert [a.connection_id for a in result.attempts] == [
        local.connection_id,
        hosted.connection_id,
    ]
    assert result.attempts[1].rationale == "fallback:provider_unavailable"
    assert result.attempts[0].admission_id != result.attempts[1].admission_id
    admitted = db.fetchall("SELECT outcome FROM model_admission_audit")
    assert [r["outcome"] for r in admitted].count("prepared_fixture_only") == 2


@pytest.mark.asyncio
async def test_fallback_cannot_widen_data_grants(setup):
    service, lease, evidence, local, hosted, _, _, db = setup
    hosted_calls = []
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted, DOWN, lambda r: hosted_calls.append(r) or GOOD(r)),
        max_attempts=3,
    )
    # Unclassified evidence is local-only: the hosted fallback is excluded.
    assert hosted_calls == []
    assert result.exhausted
    assert [e.reason for e in result.excluded] == ["admission_denied"]
    assert any(r["outcome"] == "admission_denied" for r in rows(db))


@pytest.mark.asyncio
async def test_non_error_outcomes_do_not_fall_back(setup):
    service, lease, evidence, local, hosted, policies, _, _ = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    refusal = {
        "model": "fixture-model",
        "choices": [
            {"finish_reason": "content_filter", "message": {"role": "assistant"}}
        ],
    }
    hosted_calls = []
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(
            local,
            hosted,
            lambda r: httpx2.Response(200, json=refusal),
            lambda r: hosted_calls.append(r) or GOOD(r),
        ),
        max_attempts=3,
    )
    assert result.response.status != "ok"
    assert len(result.attempts) == 1
    assert hosted_calls == []


@pytest.mark.asyncio
async def test_preferred_route_must_be_granted_and_is_not_silently_replaced(setup):
    service, lease, evidence, local, hosted, policies, _, db = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted),
        preferred=RouteRef(connection_id=hosted.connection_id, model="fixture-model"),
    )
    assert result.selected.connection_id == hosted.connection_id
    assert result.selected.rationale == "preferred_request"
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease,
            "member",
            (evidence.evidence_id,),
            factory(local, hosted),
            preferred=RouteRef(connection_id=hosted.connection_id, model="ungranted"),
        )
    assert rows(db)[-1]["outcome"] == "preferred_route_ineligible"


@pytest.mark.asyncio
async def test_unsupported_and_unadmitted_capabilities_are_excluded(setup):
    service, lease, evidence, local, hosted, policies, _, db = setup
    deepseek = service.connections.create(
        "org",
        "admin",
        ModelConnectionCreate(
            name="DeepSeek", provider="deepseek", models=["fixture-model"], enabled=True
        ),
    )
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    policies.put(
        "org",
        "admin",
        ModelPolicyWrite(
            expected_version=1,
            grants=(
                PolicyGrant(
                    role="triage",
                    connection_id=deepseek.connection_id,
                    connection_version=1,
                    models=("fixture-model",),
                ),
                PolicyGrant(
                    role="triage",
                    connection_id=hosted.connection_id,
                    connection_version=1,
                    models=("fixture-model",),
                ),
            ),
        ),
    )
    result = await router(setup).route_fixture(
        lease,
        "member",
        (evidence.evidence_id,),
        factory(local, hosted),
        capabilities=frozenset({"structured_output", "native_schema"}),
    )
    assert result.selected.connection_id == hosted.connection_id
    assert result.excluded[0].reason == "unsupported_capability"
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease,
            "member",
            (evidence.evidence_id,),
            factory(local, hosted),
            capabilities=frozenset({"structured_output", "tool_calls"}),
        )
    assert rows(db)[-1]["outcome"] == "no_eligible_route"


@pytest.mark.asyncio
async def test_stale_connection_version_and_disabled_connection_are_excluded(setup):
    service, lease, evidence, local, hosted, _, _, db = setup
    service.connections.update(
        "org",
        "admin",
        local.connection_id,
        ModelConnectionUpdate(expected_version=1, name="Renamed"),
    )
    service.connections.update(
        "org",
        "admin",
        hosted.connection_id,
        ModelConnectionUpdate(expected_version=1, enabled=False),
    )
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease, "member", (evidence.evidence_id,), factory(local, hosted)
        )
    reasons = sorted(r["outcome"] for r in rows(db) if r["kind"] == "excluded")
    assert reasons == ["connection_unavailable", "connection_version_mismatch"]


@pytest.mark.asyncio
async def test_missing_transport_is_excluded_not_replaced_by_scripted_output(setup):
    service, lease, evidence, local, hosted, _, _, _ = setup
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease, "member", (evidence.evidence_id,), lambda connection: None
        )


@pytest.mark.asyncio
async def test_revocation_during_attempt_stops_routing_without_fallback(setup):
    service, lease, evidence, local, hosted, policies, _, db = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    hosted_calls = []

    def revoke(req):
        policies.put(
            "org",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=(), enabled=False),
        )
        return httpx2.Response(503)

    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease,
            "member",
            (evidence.evidence_id,),
            factory(local, hosted, revoke, lambda r: hosted_calls.append(r) or GOOD(r)),
            max_attempts=2,
        )
    assert hosted_calls == []
    assert rows(db)[-1]["kind"] == "attempt_denied"


@pytest.mark.asyncio
@pytest.mark.parametrize("attempts", [0, 4, True])
async def test_invalid_attempt_bounds_are_rejected(setup, attempts):
    service, lease, evidence, local, hosted, _, _, _ = setup
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease,
            "member",
            (evidence.evidence_id,),
            factory(local, hosted),
            max_attempts=attempts,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", ["viewer", "missing"])
async def test_non_operators_cannot_route(setup, actor):
    service, lease, evidence, local, hosted, _, _, _ = setup
    with pytest.raises(ModelRoutingDeniedError):
        await router(setup).route_fixture(
            lease, actor, (evidence.evidence_id,), factory(local, hosted)
        )


@pytest.mark.asyncio
async def test_routing_audit_is_immutable_and_secret_free(setup):
    service, lease, evidence, local, hosted, _, _, db = setup
    _ = await router(setup).route_fixture(
        lease, "member", (evidence.evidence_id,), factory(local, hosted)
    )
    text = json.dumps(rows(db))
    for secret in ("evidence-secret", "private@example.test", "objective-secret"):
        assert secret not in text
    with pytest.raises(Exception, match="immutable"):
        db.execute("UPDATE model_routing_audit SET outcome='x'")
    with pytest.raises(Exception, match="immutable"):
        db.execute("DELETE FROM model_routing_audit")
