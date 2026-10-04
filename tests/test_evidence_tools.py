"""Evidence read tools over a temporary database: scoping, bounds and grants."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database
from terminus.toolkit.catalog import load_catalog
from terminus.toolkit.context import ReadResource, ToolReadPolicyStore
from terminus.toolkit.evidence_tools import (
    EVIDENCE_TOOL_IDS,
    MAX_CITATIONS,
    cited_evidence_ids,
)
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.readers import InvestigationReadService

NOW = datetime(2026, 10, 4, 12, tzinfo=UTC)
ALL = ("evidence.get", "evidence.timeline", "evidence.validate_citations")
FIVE = {
    "incident.get",
    "alerts.search",
    "identity.auth_events",
    "endpoint.agent",
    "collection.coverage",
}


@pytest.fixture
def env(tmp_path):
    db = Database(str(tmp_path / "evidence-tools.db"))
    for org in ("org", "other"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, NOW.isoformat()),
        )
    for actor, role in (("admin", "admin"), ("member", "member")):
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (actor, f"{actor}@example.test", "hash", actor, NOW.isoformat()),
        )
        db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", actor, role))
    for org, incident in (
        ("org", "incident"),
        ("org", "incident-2"),
        ("other", "foreign"),
    ):
        db.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at,raw_payload_json) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                incident,
                org,
                f"a-{incident}",
                "high",
                "high",
                "s",
                "[]",
                "standard",
                NOW.isoformat(),
                json.dumps({"timestamp": NOW.isoformat()}),
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
            "response_planner": ALL,
            "evidence_reporting": ("evidence.get",),
            "triage": ("evidence.get", "incident.get"),
        },
        ("terminus_store",),
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

    def evidence(org, incident, when, content=None):
        task = scheduler.records.create_incident_task(
            org, incident, "investigation", "triage", "seed"
        )
        return scheduler.records.create_evidence(
            org, task.task_id, "seed-source", when, content=content or {"n": 1}
        )

    def make(role="response_planner"):
        task = scheduler.records.create_incident_task(
            "org", "incident", "investigation", role, "go"
        )
        scheduler.enqueue_task("org", task.task_id)
        lease = scheduler.claim_next("owner", f"w-{task.task_id}", [role])
        assert lease is not None
        return InvestigationReadService("org", scheduler, policies), lease

    yield make, evidence, policies, scheduler
    db.close()


def query(resource="incident-ref", kind="evidence", span=30):
    return ReadQuery(
        resource_id=resource,
        start=NOW - timedelta(minutes=span),
        end=NOW,
        event_kind=kind,
    )


async def run(service, lease, tool, ids=(), q=None, actor="member"):
    with cited_evidence_ids(ids):
        return await service.execute(lease, actor, tool, q or query())


@pytest.mark.asyncio
async def test_get_returns_bounded_metadata_without_content(env):
    make, evidence, _, scheduler = env
    record = evidence(
        "org", "incident", NOW - timedelta(minutes=5), {"payload": "x" * 500}
    )
    service, lease = make()
    result = await run(service, lease, "evidence.get", [record.evidence_id])
    assert result.status == "ok"
    row = result.data[0]
    assert row["evidence_id"] == record.evidence_id
    assert row["content_hash"] == record.content_hash
    assert "xxxx" not in result.model_dump_json()
    stored = scheduler.records.get_evidence("org", result.evidence[0].evidence_id)
    assert stored.content["tool_id"] == "evidence.get"


@pytest.mark.asyncio
async def test_foreign_and_missing_evidence_are_indistinguishable(env):
    make, evidence, _, _ = env
    foreign_org = evidence("other", "foreign", NOW - timedelta(minutes=5))
    foreign_incident = evidence("org", "incident-2", NOW - timedelta(minutes=5))
    service, lease = make()
    outcomes = []
    for evidence_id in (
        foreign_org.evidence_id,
        foreign_incident.evidence_id,
        "missing-id",
        "bad id!",
    ):
        result = await run(service, lease, "evidence.get", [evidence_id])
        outcomes.append((result.status, result.error_code, result.gaps, result.data))
    assert len(set(map(repr, outcomes))) == 1
    assert outcomes[0][:2] == ("unavailable", "evidence_not_found")


@pytest.mark.asyncio
async def test_get_requires_exactly_one_id_and_window(env):
    make, evidence, _, _ = env
    old = evidence("org", "incident", NOW - timedelta(hours=3))
    service, lease = make()
    none = await run(service, lease, "evidence.get", [])
    assert none.error_code == "single_evidence_id_required"
    outside = await run(service, lease, "evidence.get", [old.evidence_id])
    assert outside.error_code == "evidence_outside_query_window"


@pytest.mark.asyncio
async def test_timeline_is_ordered_incident_scoped_and_excludes_own_output(env):
    make, evidence, _, _ = env
    late = evidence("org", "incident", NOW - timedelta(minutes=1))
    early = evidence("org", "incident", NOW - timedelta(minutes=20))
    evidence("org", "incident-2", NOW - timedelta(minutes=10))
    evidence("other", "foreign", NOW - timedelta(minutes=10))
    service, lease = make()
    first = await run(service, lease, "evidence.timeline")
    expected = [early.evidence_id, late.evidence_id]
    assert [r["evidence_id"] for r in first.data] == expected
    assert first.status == "ok"
    assert first.coverage == "complete"
    again = await run(service, lease, "evidence.timeline")
    assert [r["evidence_id"] for r in again.data] == expected


@pytest.mark.asyncio
async def test_empty_timeline_is_an_explicit_gap_not_success(env):
    make, _, _, _ = env
    service, lease = make()
    result = await run(service, lease, "evidence.timeline")
    assert result.status == "partial"
    assert result.coverage == "incomplete"
    assert result.data is None
    assert result.gaps


@pytest.mark.asyncio
async def test_timeline_truncation_is_flagged(env):
    make, evidence, _, _ = env
    for index in range(5):
        evidence("org", "incident", NOW - timedelta(minutes=10 - index))
    service, lease = make()
    bounded = query().model_copy(update={"page_size": 1, "max_pages": 2})
    result = await run(service, lease, "evidence.timeline", q=bounded)
    assert result.truncated
    assert result.status == "partial"
    assert len(result.data) == 2
    assert result.gaps


@pytest.mark.asyncio
async def test_validate_citations_valid_foreign_and_missing(env):
    make, evidence, _, _ = env
    good = evidence("org", "incident", NOW - timedelta(minutes=5))
    foreign = evidence("other", "foreign", NOW - timedelta(minutes=5))
    sibling = evidence("org", "incident-2", NOW - timedelta(minutes=5))
    service, lease = make()
    result = await run(
        service,
        lease,
        "evidence.validate_citations",
        [
            good.evidence_id,
            foreign.evidence_id,
            sibling.evidence_id,
            "missing-id",
            good.evidence_id,
        ],
    )
    rows = result.data["citations"]
    assert [r["status"] for r in rows] == [
        "valid",
        "not_found",
        "not_found",
        "not_found",
    ]
    assert rows[1] == {"evidence_id": foreign.evidence_id, "status": "not_found"}
    assert set(rows[1]) == set(rows[3])
    assert result.status == "partial"
    assert result.data["claim_support"] == "not_verified"
    clean = await run(service, lease, "evidence.validate_citations", [good.evidence_id])
    assert clean.status == "ok"


@pytest.mark.asyncio
async def test_validate_citations_bounds(env):
    make, _, _, _ = env
    service, lease = make()
    many = [f"id-{n}" for n in range(MAX_CITATIONS + 1)]
    result = await run(service, lease, "evidence.validate_citations", many)
    assert result.error_code == "too_many_citations"
    result = await run(service, lease, "evidence.validate_citations", [])
    assert result.error_code == "citation_ids_required"


@pytest.mark.asyncio
async def test_unbound_or_endpoint_resource_and_kind_rejected(env):
    make, evidence, _, _ = env
    record = evidence("org", "incident", NOW - timedelta(minutes=5))
    service, lease = make()
    ids = [record.evidence_id]
    unbound = await run(service, lease, "evidence.get", ids, q=query("nope"))
    assert unbound.status == "denied"
    endpoint = await run(service, lease, "evidence.get", ids, q=query("endpoint-ref"))
    assert endpoint.error_code == "incident_resource_required"
    kind = await run(service, lease, "evidence.get", ids, q=query(kind="detection"))
    assert kind.error_code == "query_kind_not_supported"


@pytest.mark.asyncio
async def test_role_not_granted_by_catalog_is_denied_even_if_policy_lists_it(env):
    make, evidence, _, _ = env
    record = evidence("org", "incident", NOW - timedelta(minutes=5))
    service, lease = make("triage")
    result = await run(service, lease, "evidence.get", [record.evidence_id])
    assert result.status == "denied"
    assert result.error_code == "tool_not_granted"


@pytest.mark.asyncio
async def test_policy_not_granting_tool_is_denied(env):
    make, evidence, _, _ = env
    record = evidence("org", "incident", NOW - timedelta(minutes=5))
    service, lease = make("evidence_reporting")
    result = await run(service, lease, "evidence.timeline")
    assert result.status == "denied"
    ok = await run(service, lease, "evidence.get", [record.evidence_id])
    assert ok.status == "ok"


@pytest.mark.asyncio
async def test_revoked_grant_denies(env):
    make, evidence, policies, _ = env
    record = evidence("org", "incident", NOW - timedelta(minutes=5))
    service, lease = make()
    _ = policies.revoke_policy("admin", "org", "incident", expected_version=3)
    result = await run(service, lease, "evidence.get", [record.evidence_id])
    assert result.status == "denied"
    assert result.data is None


@pytest.mark.asyncio
async def test_ids_cannot_come_from_model_arguments(env):
    make, evidence, _, _ = env
    record = evidence("org", "incident", NOW - timedelta(minutes=5))
    service, lease = make()
    smuggled = {
        "resource_id": "incident-ref",
        "start": (NOW - timedelta(minutes=30)).isoformat(),
        "end": NOW.isoformat(),
        "evidence_id": record.evidence_id,
    }
    result = await service.execute(lease, "member", "evidence.get", smuggled)
    assert result.status == "denied"
    assert result.error_code == "invalid_arguments"


@pytest.mark.asyncio
async def test_existing_tools_installed_and_packaged_catalog_stays_dormant(env):
    make, _, _, _ = env
    service, _ = make()
    for name in {"incident.get", *EVIDENCE_TOOL_IDS}:
        assert service.registry.descriptor(name).availability == "available"
    for name in FIVE:
        assert service.registry.resolve is not None
        assert service.registry.descriptor(name).tool_id == name
    assert service.registry.descriptor("evidence.get").effect == "read"
    assert (
        service.registry.descriptor("evidence.validate_citations").effect
        == "local_analysis"
    )
    assert all(tool.availability != "available" for tool in load_catalog().tools)
    assert not set(EVIDENCE_TOOL_IDS) & service.registry.grants_for("triage")
    assert set(EVIDENCE_TOOL_IDS) <= service.registry.grants_for("response_planner")
