"""M03 integration: durable grants, canonical evidence and fixture-only attempts."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime

import httpx2
import pytest

from terminus.model_gateway.admission import (
    ModelAdmissionDeniedError,
    ModelAdmissionService,
)
from terminus.model_gateway.fixture_client import FixtureModelClient
from terminus.model_gateway.models import ModelConnectionCreate, ModelConnectionUpdate
from terminus.model_gateway.policy import (
    ModelPolicyStore,
    ModelPolicyWrite,
    PolicyGrant,
)
from terminus.model_gateway.safety import EndpointVerifier
from terminus.model_gateway.store import ModelConnectionStore
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "admission.db"))
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("org", "Fixture", NOW.isoformat()),
    )
    for actor, role in (("admin", "admin"), ("member", "member"), ("viewer", "viewer")):
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (actor, f"{actor}@example.test", "hash", actor, NOW.isoformat()),
        )
        db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", actor, role))
    db.execute(
        "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (
            "incident",
            "org",
            "alert-1",
            "high",
            "high",
            "Fixture",
            "[]",
            "standard",
            NOW.isoformat(),
        ),
    )
    scheduler = SchedulerStore(db, clock=lambda: NOW)
    scheduler.acquire_coordinator("owner", lease_seconds=300)
    task = scheduler.records.create_incident_task(
        "org",
        "incident",
        "alert_handling",
        "triage",
        "password=objective-secret-never-export",
    )
    evidence = scheduler.records.create_evidence(
        "org",
        task.task_id,
        "fixture",
        NOW,
        content={
            "password": "evidence-secret",
            "email": "private@example.test",
            "finding": "failed authentication",
        },
    )
    scheduler.enqueue_task("org", task.task_id)
    lease = scheduler.claim_next("owner", "worker", ["triage"])
    assert lease is not None
    connections = ModelConnectionStore(db, None)
    local = connections.create(
        "org",
        "admin",
        ModelConnectionCreate(
            name="Private",
            provider="local",
            base_url="https://models.corp.test/v1",
            models=["fixture-model"],
            enabled=True,
        ),
    )
    cloud = connections.create(
        "org",
        "admin",
        ModelConnectionCreate(
            name="Hosted", provider="openai", models=["fixture-model"], enabled=True
        ),
    )
    policies = ModelPolicyStore(db)
    grants = tuple(
        PolicyGrant(
            role="triage",
            connection_id=item.connection_id,
            connection_version=1,
            models=("fixture-model",),
            classifications=("local_only", "approved_cloud", "redacted_cloud"),
        )
        for item in (local, cloud)
    )
    policies.put("org", "admin", ModelPolicyWrite(grants=grants))
    addresses = ["10.0.0.2"]

    async def resolver(host):
        return tuple(addresses)

    verifier = EndpointVerifier(resolver, clock=lambda: NOW)
    service = ModelAdmissionService(scheduler, policies, connections, verifier)
    yield service, lease, evidence, local, cloud, policies, addresses, db
    db.close()


async def prepare(setup, *, cloud=False, actor="member", ids=None):
    service, lease, evidence, local, hosted, _, _, _ = setup
    return await service.prepare(
        lease,
        actor,
        (hosted if cloud else local).connection_id,
        "fixture-model",
        (evidence.evidence_id,) if ids is None else ids,
    )


def reply():
    return {
        "model": "fixture-model",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "role": "assistant",
                    "content": '{"finding":"fixture only"}',
                },
            }
        ],
    }


def client(connection, callback):
    return FixtureModelClient(
        connection.provider,
        httpx2.MockTransport(callback),
        base_url=connection.base_url,
    )


@pytest.mark.asyncio
async def test_unclassified_evidence_is_local_only_and_scrubbed(setup):
    service, _, _, local, _, _, _, db = setup
    call = await prepare(setup)
    text = call.request.model_dump_json()
    assert "evidence-secret" not in text
    assert "private@example.test" not in text
    assert "objective-secret" not in text
    assert "[REDACTED" in text
    with pytest.raises(ModelAdmissionDeniedError):
        await prepare(setup, cloud=True)
    result = await service.respond_fixture(
        call, client(local, lambda req: httpx2.Response(200, json=reply()))
    )
    assert result.status == "ok"
    with pytest.raises(ModelAdmissionDeniedError):
        await service.respond_fixture(
            call, client(local, lambda req: httpx2.Response(200, json=reply()))
        )
    records = db.fetchall("SELECT request_digest,outcome FROM model_admission_audit")
    assert [row["outcome"] for row in records] == [
        "prepared_fixture_only",
        "fixture_finished",
    ]
    assert "evidence-secret" not in json.dumps(records)


@pytest.mark.asyncio
async def test_admin_classified_cloud_evidence_is_permitted_without_raw_secrets(setup):
    service, _, evidence, _, hosted, policies, _, _ = setup
    policies.classify_evidence("org", "admin", evidence.evidence_id, "redacted_cloud")
    call = await prepare(setup, cloud=True)
    assert call.destination is None
    seen = []

    def transport(req):
        seen.append(req.content.decode())
        return httpx2.Response(200, json=reply())

    result = await service.respond_fixture(call, client(hosted, transport))
    assert result.status == "ok"
    assert "evidence-secret" not in seen[0]
    assert "private@example.test" not in seen[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("actor", ["viewer", "missing"])
async def test_non_operators_cannot_prepare(setup, actor):
    with pytest.raises(ModelAdmissionDeniedError):
        await prepare(setup, actor=actor)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        "policy",
        "membership",
        "classification",
        "connection",
        "dns",
        "payload",
        "destination",
    ],
)
async def test_fresh_attempt_rejects_changed_authority_and_destination(setup, change):
    service, _, evidence, local, hosted, policies, addresses, db = setup
    call = await prepare(setup)
    if change == "policy":
        policies.put(
            "org",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=(), enabled=False),
        )
    elif change == "membership":
        db.execute(
            "DELETE FROM memberships WHERE org_id=? AND user_id=?", ("org", "member")
        )
    elif change == "classification":
        policies.classify_evidence(
            "org", "admin", evidence.evidence_id, "approved_cloud"
        )
    elif change == "connection":
        service.connections.update(
            "org",
            "admin",
            local.connection_id,
            ModelConnectionUpdate(expected_version=1, enabled=False),
        )
    elif change == "dns":
        addresses[:] = ["10.0.0.3"]
    elif change == "payload":
        call = call.model_copy(update={"request_digest": "0" * 64})
    target = hosted if change == "destination" else local
    calls = []
    with pytest.raises(ModelAdmissionDeniedError):
        await service.respond_fixture(
            call,
            client(
                target,
                lambda req: calls.append(req) or httpx2.Response(200, json=reply()),
            ),
        )
    assert calls == []


@pytest.mark.asyncio
async def test_revocation_during_io_cancels_provider_fixture(setup):
    service, _, _, local, _, policies, _, _ = setup
    call = await prepare(setup)
    started, stopped = asyncio.Event(), asyncio.Event()

    async def pending(req):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    operation = asyncio.create_task(
        service.respond_fixture(call, client(local, pending))
    )
    await started.wait()
    policies.put(
        "org", "admin", ModelPolicyWrite(expected_version=1, grants=(), enabled=False)
    )
    with pytest.raises(ModelAdmissionDeniedError):
        await asyncio.wait_for(operation, 1)
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_revocation_at_completion_suppresses_returned_findings(setup):
    service, _, _, local, _, policies, _, _ = setup
    call = await prepare(setup)

    def transport(req):
        policies.put(
            "org",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=(), enabled=False),
        )
        return httpx2.Response(200, json=reply())

    with pytest.raises(ModelAdmissionDeniedError):
        await service.respond_fixture(call, client(local, transport))


@pytest.mark.asyncio
async def test_copied_lease_and_unknown_evidence_cannot_broaden_scope(setup):
    service, lease, _, local, _, _, _, _ = setup
    with pytest.raises(ModelAdmissionDeniedError):
        await service.prepare(
            lease.model_copy(
                update={"task": lease.task.model_copy(update={"role": "endpoint"})}
            ),
            "member",
            local.connection_id,
            "fixture-model",
            (),
        )
    with pytest.raises(ModelAdmissionDeniedError):
        await prepare(setup, ids=("foreign-evidence",))
    with pytest.raises(ModelAdmissionDeniedError):
        await service.prepare(lease, "member", local.connection_id, "not-granted", ())


@pytest.mark.asyncio
async def test_process_restart_requires_new_admission(setup):
    service, _, _, local, _, _, _, _ = setup
    call = await prepare(setup)
    fresh = ModelAdmissionService(
        service.scheduler, service.policies, service.connections, service.verifier
    )
    with pytest.raises(ModelAdmissionDeniedError):
        await fresh.authorize(call)
    with pytest.raises(ModelAdmissionDeniedError):
        await service.prepare(
            setup[1],
            "member",
            local.connection_id,
            "fixture-model",
            (setup[2].evidence_id,),
            output_schema={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
                "description": "password=schema-secret",
            },
        )


@pytest.mark.asyncio
async def test_mutated_returned_object_cannot_replace_private_prompt_binding(setup):
    import hashlib

    service, _, _, local, _, _, _, _ = setup
    call = await prepare(setup)
    changed = call.request.model_copy(
        update={"system": "arbitrary-system", "messages": ()}
    )
    call.__dict__["request"] = changed
    call.__dict__["request_digest"] = hashlib.sha256(
        json.dumps(
            changed.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    sent = []

    def transport(req):
        sent.append(req)
        return httpx2.Response(200, json=reply())

    with pytest.raises(ModelAdmissionDeniedError):
        await service.respond_fixture(call, client(local, transport))
    assert sent == []
