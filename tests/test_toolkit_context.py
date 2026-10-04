"""Live trusted actor, lease, policy and incident-resource authorization."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orgs.models import Membership, OrganizationRole
from terminus.storage.db import Database
from terminus.toolkit.audit import ToolInvocationStore
from terminus.toolkit.catalog import load_catalog
from terminus.toolkit.context import (
    ReadContextDeniedError,
    ReadPolicyConflictError,
    ReadResource,
    ToolReadPolicyStore,
    TrustedReadContextFactory,
)
from terminus.toolkit.registry import ExecutableToolRegistry
from terminus.toolkit.models import ReadQuery


@pytest.fixture
def setup(tmp_path):
    db = Database(str(tmp_path / "context.db"))
    now = [datetime(2026, 10, 4, tzinfo=UTC)]
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("org", "Org", now[0].isoformat()),
    )
    for user_id, role in (
        ("admin", "admin"),
        ("member", "member"),
        ("viewer", "viewer"),
    ):
        db.execute(
            "INSERT INTO users VALUES(?,?,?,?,?)",
            (user_id, f"{user_id}@example.test", "hash", user_id, now[0].isoformat()),
        )
        db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", user_id, role))
    for incident in ("incident", "other-incident"):
        db.execute(
            """INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,
            summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                incident,
                "org",
                "alert",
                "high",
                "high",
                "Fixture",
                "[]",
                "standard",
                now[0].isoformat(),
            ),
        )
    scheduler = SchedulerStore(db, clock=lambda: now[0])
    task = scheduler.records.create_incident_task(
        "org", "incident", "triage", "triage", "Inspect"
    )
    scheduler.enqueue_task("org", task.task_id)
    scheduler.acquire_coordinator("coordinator", lease_seconds=300)
    lease = scheduler.claim_next("coordinator", "worker", {"triage"}, lease_seconds=60)
    registry = ExecutableToolRegistry()
    audit = ToolInvocationStore(db, clock=lambda: now[0])
    store = ToolReadPolicyStore(db)
    store.put_policy(
        "admin",
        "org",
        "incident",
        {"triage": ("incident.get", "endpoint.agent")},
        ("wazuh_manager",),
    )
    store.bind_resource(
        "admin",
        ReadResource(
            resource_id="incident-ref",
            org_id="org",
            incident_id="incident",
            kind="incident",
        ),
        expected_version=1,
    )
    store.bind_resource(
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
    factory = TrustedReadContextFactory(scheduler, registry, store, audit)
    yield factory, store, lease, now
    db.close()


def test_context_derived_from_persisted_scope_and_core_bundle(setup):
    factory, _, lease, _ = setup
    context = factory.build(lease, "member")
    assert context.org_id == "org"
    assert context.incident_id == "incident"
    assert context.run_id == lease.run_id
    assert context.role == "triage"
    assert set(context.granted_tool_ids) == {
        "incident.get",
        "endpoint.agent",
    }.intersection(factory.registry.grants_for("triage"))
    assert context.permitted_resource_ids == ("endpoint-ref", "incident-ref")
    assert context.permitted_connector_ids == ("wazuh_manager",)
    assert context.policy_version == "read-policy:3"
    assert context.budget_reservation_id.startswith("read-quota:")
    assert context.invocation_count == 0
    assert context.egress_authorized is False
    assert factory.resolve_resource(context, "endpoint-ref").agent_id == "001"
    assert factory.resolve_resource(context, "incident-ref").incident_id == "incident"
    factory.authorize(
        context.model_copy(
            update={"invocation_id": "invocation", "invocation_count": 1}
        )
    )


@pytest.mark.parametrize("actor", ["viewer", "unknown"])
def test_viewers_nonmembers_denied(setup, actor):
    factory, _, lease, _ = setup
    with pytest.raises(ReadContextDeniedError):
        factory.build(lease, actor)


@pytest.mark.parametrize("change", ["removed", "demoted"])
def test_live_membership_revocation_denies_issued_context(setup, change):
    factory, store, lease, _ = setup
    context = factory.build(lease, "member")
    if change == "removed":
        store.memberships.delete(OrgId("org"), UserId("member"))
    else:
        store.memberships.update(
            Membership(
                org_id=OrgId("org"),
                user_id=UserId("member"),
                role=OrganizationRole.VIEWER,
            )
        )
    with pytest.raises(ReadContextDeniedError):
        factory.authorize(context)


@pytest.mark.parametrize("change", ["policy", "resource", "remap"])
def test_live_policy_changes_invalidate_old_context(setup, change):
    factory, store, lease, _ = setup
    context = factory.build(lease, "member")
    if change == "policy":
        store.revoke_policy("admin", "org", "incident", expected_version=3)
    elif change == "resource":
        store.revoke_resource(
            "admin", "org", "incident", "endpoint-ref", expected_version=3
        )
    else:
        store.bind_resource(
            "admin",
            ReadResource(
                resource_id="endpoint-ref",
                org_id="org",
                incident_id="incident",
                kind="endpoint",
                agent_id="002",
            ),
            expected_version=3,
        )
    with pytest.raises(ReadContextDeniedError):
        factory.resolve_resource(context, "endpoint-ref")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("granted_tool_ids", ("alerts.search",)),
        ("permitted_resource_ids", ("foreign",)),
        ("permitted_connector_ids", ("wazuh_indexer",)),
        ("egress_authorized", True),
        ("budget_reservation_id", "forged"),
    ],
)
def test_context_forgery_denied(setup, field, value):
    factory, _, lease, _ = setup
    context = factory.build(lease, "member")
    with pytest.raises(ReadContextDeniedError):
        factory.authorize(context.model_copy(update={field: value}))


@pytest.mark.parametrize("condition", ["cancel", "expired", "coordinator_expired"])
def test_live_lease_fencing(setup, condition):
    factory, _, lease, now = setup
    context = factory.build(lease, "admin")
    if condition == "cancel":
        factory.scheduler.request_cancel("org", lease.task_id)
    else:
        now[0] += timedelta(seconds=61 if condition == "expired" else 301)
    with pytest.raises(ReadContextDeniedError):
        factory.authorize(context)


def test_spoofed_task_role_never_becomes_trusted(setup):
    factory, _, lease, _ = setup
    spoofed = lease.model_copy(
        update={"task": lease.task.model_copy(update={"role": "endpoint"})}
    )
    with pytest.raises(ReadContextDeniedError):
        factory.build(spoofed, "admin")


def test_resource_not_bound_to_incident_is_denied(setup):
    factory, store, lease, _ = setup
    store.put_policy(
        "admin", "org", "other-incident", {"triage": ("incident.get",)}, ()
    )
    store.bind_resource(
        "admin",
        ReadResource(
            resource_id="foreign",
            org_id="org",
            incident_id="other-incident",
            kind="endpoint",
            agent_id="999",
        ),
        expected_version=1,
    )
    context = factory.build(lease, "admin")
    with pytest.raises(ReadContextDeniedError):
        factory.resolve_resource(context, "foreign")
    # Inventory/provider IDs are never implicit resource grants.
    with pytest.raises(ReadContextDeniedError):
        factory.resolve_resource(context, "001")


@pytest.mark.parametrize("actor", ["member", "viewer", "unknown"])
def test_only_admin_can_configure(setup, actor):
    _, store, _, _ = setup
    with pytest.raises(ReadContextDeniedError):
        store.put_policy(
            actor,
            "org",
            "incident",
            {"triage": ("incident.get",)},
            (),
            expected_version=3,
        )
    with pytest.raises(ReadContextDeniedError):
        store.bind_resource(
            actor,
            ReadResource(
                resource_id="new", org_id="org", incident_id="incident", kind="incident"
            ),
            expected_version=3,
        )
    with pytest.raises(ReadContextDeniedError):
        store.revoke_policy(actor, "org", "incident", expected_version=3)


def test_version_conflict_and_canonical_incident_scope(setup):
    _, store, _, _ = setup
    with pytest.raises(ReadPolicyConflictError):
        store.put_policy("admin", "org", "incident", {}, (), expected_version=2)
    with pytest.raises(ReadContextDeniedError):
        store.put_policy("admin", "org", "missing", {}, ())
    assert store.get_policy("org", "incident").version == 3


@pytest.mark.parametrize(
    "agent_id",
    [None, "1", "123456789", "../001", "https://example.test/001", "001?x", "abc"],
)
def test_endpoint_identity_is_strict(agent_id):
    with pytest.raises(ValidationError):
        ReadResource(
            resource_id="endpoint",
            org_id="org",
            incident_id="incident",
            kind="endpoint",
            agent_id=agent_id,
        )


def test_incident_resource_cannot_carry_agent_identity():
    with pytest.raises(ValidationError):
        ReadResource(
            resource_id="incident",
            org_id="org",
            incident_id="incident",
            kind="incident",
            agent_id="001",
        )


def test_restart_persists_policy_resource_but_requires_new_issuance(setup):
    factory, store, lease, _ = setup
    context = factory.build(lease, "member")
    restarted = ToolReadPolicyStore(store.db)
    new_factory = TrustedReadContextFactory(
        factory.scheduler, factory.registry, restarted, factory.audit
    )
    assert restarted.get_policy("org", "incident").version == 3
    assert len(restarted.resources("org", "incident")) == 2
    with pytest.raises(ReadContextDeniedError):
        new_factory.authorize(context)
    new_factory.authorize(new_factory.build(lease, "member"))


@pytest.mark.parametrize("invalid", ["future", "unknown", "dispatch"])
def test_policy_cannot_enable_future_or_effect_tools(setup, invalid):
    _, store, _, _ = setup
    tools = load_catalog().tools
    tool_id = (
        "unknown"
        if invalid == "unknown"
        else next(
            item.tool_id
            for item in tools
            if (
                item.release == "future"
                if invalid == "future"
                else item.effect == "dispatch"
            )
        )
    )
    with pytest.raises(ValueError):
        store.put_policy(
            "admin", "org", "incident", {"triage": (tool_id,)}, (), expected_version=3
        )


def test_policy_cannot_enable_unknown_connector(setup):
    _, store, _, _ = setup
    with pytest.raises(ValueError):
        store.put_policy(
            "admin", "org", "incident", {}, ("arbitrary-url",), expected_version=3
        )


def test_factory_reads_task_wide_durable_attempt_count(setup):
    factory, store, lease, now = setup
    store.put_policy(
        "admin",
        "org",
        "incident",
        {"triage": ("incident.get",)},
        ("terminus_store",),
        expected_version=3,
    )
    context = factory.build(lease, "member")
    descriptor = factory.registry.descriptor("incident.get").model_copy(
        update={"availability": "available"}
    )
    query = ReadQuery(
        resource_id="incident-ref", start=now[0] - timedelta(minutes=5), end=now[0]
    )
    for _ in range(20):
        factory.audit.reserve(descriptor, context, query)
    rebuilt = factory.build(lease, "member")
    assert rebuilt.invocation_count == 20
    # The twentieth handler can still reauthorize after its reservation;
    # audit admission prevents a twenty-first request.
    factory.authorize(context)
    assert len(factory.audit.list_pending("org", lease.task_id)) == 20


def test_factory_bounds_issued_context_retention(setup):
    factory, _, lease, _ = setup
    oldest = factory.build(lease, "member")
    for _ in range(1024):
        newest = factory.build(lease, "member")
    factory.authorize(newest)
    with pytest.raises(ReadContextDeniedError):
        factory.authorize(oldest)


def test_admin_demotion_prevents_further_policy_writes(setup):
    _, store, _, _ = setup
    store.memberships.update(
        Membership(
            org_id=OrgId("org"), user_id=UserId("admin"), role=OrganizationRole.MEMBER
        )
    )
    with pytest.raises(ReadContextDeniedError):
        store.revoke_resource(
            "admin", "org", "incident", "endpoint-ref", expected_version=3
        )
    assert store.get_policy("org", "incident").version == 3
