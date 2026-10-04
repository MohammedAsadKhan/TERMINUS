"""Fixture-backed real composition, with server grants and provider separation."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
from pydantic import SecretStr

from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database
from terminus.toolkit.context import ReadResource, ToolReadPolicyStore
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.readers import InvestigationReadService
from terminus.toolkit.wazuh_readers import (
    WazuhIndexerReader,
    WazuhIndexerSettings,
    WazuhManagerReader,
    WazuhManagerSettings,
)

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
INDEX = "wazuh-alerts-4.x-2026.10.04"


def event(agent="001", size=0):
    return {
        "_id": "event-1",
        "_index": INDEX,
        "sort": [int(NOW.timestamp() * 1000), "manager", "event-1", INDEX],
        "_source": {
            "id": "event-1",
            "timestamp": NOW.isoformat(),
            "agent": {"id": agent},
            "manager": {"name": "manager"},
            "rule": {"groups": ["authentication_failed"]},
            "full_log": "x" * size,
        },
    }


def search(items):
    return {
        "timed_out": False,
        "_shards": {"failed": 0},
        "hits": {"total": {"value": len(items), "relation": "eq"}, "hits": items},
    }


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "read-service.db"))
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
        "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at,raw_payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (
            "incident",
            "org",
            "alert-1",
            "high",
            "high",
            "Not raw evidence",
            "[]",
            "standard",
            NOW.isoformat(),
            json.dumps(
                {
                    "id": "alert-1",
                    "timestamp": NOW.isoformat(),
                    "agent": {"id": "001"},
                    "full_log": "failed authentication",
                }
            ),
        ),
    )
    scheduler = SchedulerStore(db, clock=lambda: NOW)
    scheduler.acquire_coordinator("owner", lease_seconds=300)
    policies = ToolReadPolicyStore(db)
    policies.put_policy(
        "admin",
        "org",
        "incident",
        {
            "triage": ("incident.get", "alerts.search", "collection.coverage"),
            "identity": ("identity.auth_events",),
            "endpoint": ("endpoint.agent",),
        },
        ("terminus_store", "wazuh_manager", "wazuh_indexer"),
    )
    policies.bind_resource(
        "admin",
        ReadResource(
            resource_id="incident-ref",
            org_id="org",
            incident_id="incident",
            kind="incident",
        ),
        expected_version=1,
    )
    policies.bind_resource(
        "admin",
        ReadResource(
            resource_id="endpoint-ref",
            org_id="org",
            incident_id="incident",
            kind="endpoint",
            agent_id="001",
        ),
        expected_version=2,
    )
    clients = []
    requests = []

    def make(
        *,
        role="triage",
        manager=True,
        indexer=True,
        index_items=None,
        on_index=None,
        index_transport=None,
    ):
        task = scheduler.records.create_incident_task(
            "org", "incident", "investigation", role, "Inspect source"
        )
        scheduler.enqueue_task("org", task.task_id)
        lease = scheduler.claim_next("owner", f"worker-{task.task_id}", [role])
        assert lease is not None

        def manager_wire(request):
            requests.append(request)
            if request.url.path.endswith("authenticate"):
                return httpx2.Response(200, text="fixture-jwt")
            assert request.url.path == "/agents"
            assert request.url.params["agents_list"] == "001"
            return httpx2.Response(
                200,
                json={
                    "error": 0,
                    "data": {
                        "total_affected_items": 1,
                        "failed_items": [],
                        "total_failed_items": 0,
                        "affected_items": [
                            {
                                "id": "001",
                                "name": "real-fixture-host",
                                "status": "active",
                                "lastKeepAlive": NOW.isoformat(),
                            }
                        ],
                    },
                },
            )

        def index_wire(request):
            requests.append(request)
            if on_index:
                on_index()
            return httpx2.Response(
                200, json=search([event()] if index_items is None else index_items)
            )

        manager_client = httpx2.AsyncClient(
            transport=httpx2.MockTransport(manager_wire)
        )
        indexer_client = httpx2.AsyncClient(
            transport=httpx2.MockTransport(index_transport or index_wire)
        )
        clients.extend((manager_client, indexer_client))
        manager_reader = (
            WazuhManagerReader(
                WazuhManagerSettings(
                    org_id="org",
                    manager_url="https://manager.test:55000",
                    username=SecretStr("manager-user"),
                    password=SecretStr("manager-secret"),
                ),
                manager_client,
            )
            if manager
            else None
        )
        indexer_reader = (
            WazuhIndexerReader(
                WazuhIndexerSettings(
                    org_id="org",
                    indexer_url="https://indexer.test:9200",
                    username=SecretStr("indexer-user"),
                    password=SecretStr("indexer-secret"),
                ),
                indexer_client,
            )
            if indexer
            else None
        )
        return InvestigationReadService(
            "org", scheduler, policies, manager=manager_reader, indexer=indexer_reader
        ), lease

    yield make, policies, scheduler, requests
    for client in clients:
        asyncio.run(client.aclose())
    db.close()


def query(resource="endpoint-ref", kind="evidence"):
    return ReadQuery(
        resource_id=resource,
        start=NOW - timedelta(minutes=30),
        end=NOW,
        event_kind=kind,
    )


@pytest.mark.asyncio
async def test_incident_reader_uses_canonical_raw_source_and_durable_evidence(setup):
    make, _, scheduler, requests = setup
    service, lease = make(manager=False, indexer=False)
    result = await service.execute(
        lease, "member", "incident.get", query("incident-ref")
    )
    assert result.status == "ok"
    assert result.data[0]["raw_payload"]["full_log"] == "failed authentication"
    assert "Not raw evidence" not in result.model_dump_json()
    assert requests == []
    stored = scheduler.records.get_evidence("org", result.evidence[0].evidence_id)
    assert (
        stored.content["invocation_id"]
        == service.audit.list_invocations("org", lease.task_id)[0].invocation_id
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("role", "tool"),
    [
        ("triage", "alerts.search"),
        ("identity", "identity.auth_events"),
        ("endpoint", "endpoint.agent"),
    ],
)
async def test_real_reader_composition_scopes_requests_and_uses_separate_credentials(
    setup, role, tool
):
    make, _, _, requests = setup
    service, lease = make(role=role)
    result = await service.execute(lease, "member", tool, query())
    assert result.status == "ok", result
    assert result.evidence
    assert "manager-secret" not in result.model_dump_json()
    assert "indexer-secret" not in result.model_dump_json()
    if tool == "endpoint.agent":
        assert {r.url.host for r in requests} == {"manager.test"}
        assert result.data[0]["connectivity"] == "active"
        assert "healthy" not in result.model_dump_json()
    else:
        assert {r.url.host for r in requests} == {"indexer.test"}
        payload = json.loads(requests[0].content)
        assert {"term": {"agent.id": "001"}} in payload["query"]["bool"]["filter"]
        if role == "identity":
            assert "authentication_failed" in json.dumps(payload)


@pytest.mark.asyncio
async def test_coverage_is_observations_with_gap_not_a_healthy_host_claim(setup):
    make, _, _, requests = setup
    service, lease = make()
    result = await service.execute(
        lease, "member", "collection.coverage", query(kind="coverage")
    )
    assert result.status == "partial", result
    assert len(result.evidence) == 2
    assert result.coverage == "incomplete"
    assert any("host health" in gap for gap in result.gaps)
    assert {r.url.host for r in requests} == {"manager.test", "indexer.test"}


@pytest.mark.asyncio
async def test_coverage_with_no_alerts_keeps_sensor_observation_and_explicit_gap(setup):
    make, _, _, _ = setup
    service, lease = make(index_items=[])
    result = await service.execute(
        lease, "member", "collection.coverage", query(kind="coverage")
    )
    assert result.status == "partial", result
    assert len(result.evidence) == 1
    assert any("no usable observations" in gap for gap in result.gaps)


@pytest.mark.asyncio
async def test_empty_indexer_collection_has_provenance_without_fabricated_events(setup):
    make, _, scheduler, _ = setup
    service, lease = make(index_items=[])
    result = await service.execute(lease, "member", "alerts.search", query())
    assert result.status == "empty"
    assert result.data is None
    assert result.evidence == ()
    assert result.provenance[0].source_event_ids == ()
    assert scheduler.records.list_evidence("org") == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "viewer",
        "foreign-resource",
        "model-scope",
        "wrong-kind",
        "missing-source",
        "future-tool",
    ],
)
async def test_denied_or_unavailable_reads_do_not_contact_providers(setup, mode):
    make, _, _, requests = setup
    service, lease = make(indexer=mode != "missing-source")
    args = query()
    actor = "viewer" if mode == "viewer" else "member"
    if mode == "foreign-resource":
        args = query("foreign-ref")
    elif mode == "model-scope":
        args = args.model_dump(mode="json") | {"org_id": "foreign"}
    elif mode == "wrong-kind":
        args = query("incident-ref")
    tool = "identity.directory" if mode == "future-tool" else "alerts.search"
    result = await service.execute(lease, actor, tool, args)
    assert result.status in {"denied", "unavailable", "unsupported"}
    assert requests == []
    assert not result.evidence
    assert result.data is None


@pytest.mark.asyncio
async def test_policy_revocation_during_provider_io_suppresses_data_and_evidence(setup):
    make, policies, scheduler, _ = setup
    service, lease = make(
        on_index=lambda: policies.revoke_policy(
            "admin", "org", "incident", expected_version=3
        )
    )
    result = await service.execute(lease, "member", "alerts.search", query())
    assert result.status == "denied", result
    assert result.data is None
    assert result.evidence == ()
    assert scheduler.records.list_evidence("org") == []


@pytest.mark.asyncio
async def test_foreign_provider_payload_is_not_persisted(setup):
    make, _, scheduler, _ = setup
    service, lease = make(index_items=[event(agent="999")])
    result = await service.execute(lease, "member", "alerts.search", query())
    assert result.status == "error"
    assert scheduler.records.list_evidence("org") == []


@pytest.mark.asyncio
async def test_large_observation_is_partial_and_no_output_is_oversized(setup):
    make, _, _, _ = setup
    service, lease = make(index_items=[event(size=40000)])
    result = await service.execute(lease, "member", "alerts.search", query())
    assert result.status == "partial", result
    assert result.truncated
    assert len(result.model_dump_json().encode()) <= 65536


@pytest.mark.asyncio
async def test_revocation_while_request_is_pending_cancels_and_audits_unknown(setup):
    make, policies, _, _ = setup
    started, stopped = asyncio.Event(), asyncio.Event()

    async def pending(request):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    service, lease = make(index_transport=pending)
    call = asyncio.create_task(
        service.execute(lease, "member", "alerts.search", query())
    )
    await started.wait()
    policies.revoke_policy("admin", "org", "incident", expected_version=3)
    result = await asyncio.wait_for(call, 1)
    await asyncio.wait_for(stopped.wait(), 1)
    assert result.error_code == "execution_unknown"
    assert result.data is None
    assert service.audit.list_invocations("org", lease.task_id)[0].outcome == "unknown"


@pytest.mark.asyncio
async def test_missing_source_timestamp_is_a_gap_not_ingestion_freshness(setup):
    make, _, scheduler, requests = setup
    scheduler.db.execute(
        "UPDATE incidents SET raw_payload_json=? WHERE ticket_id=?",
        (
            json.dumps({"id": "alert-1", "full_log": "source without timestamp"}),
            "incident",
        ),
    )
    service, lease = make()
    result = await service.execute(
        lease, "member", "incident.get", query("incident-ref")
    )
    assert result.status == "unavailable"
    assert result.data is None
    assert not result.evidence
    assert requests == []


@pytest.mark.asyncio
async def test_revocation_before_final_audit_suppresses_returned_observations(
    setup, monkeypatch
):
    make, policies, _, _ = setup
    service, lease = make()
    validate = service.validator.validate_result

    def revoke_after_validation(descriptor, context, result):
        validate(descriptor, context, result)
        policies.revoke_policy("admin", "org", "incident", expected_version=3)

    monkeypatch.setattr(service.validator, "validate_result", revoke_after_validation)
    result = await service.execute(lease, "member", "alerts.search", query())
    assert result.status == "denied"
    assert result.error_code == "authorization_changed"
    assert result.data is None
    assert not result.evidence
    assert service.audit.list_invocations("org", lease.task_id)[0].outcome == "denied"
