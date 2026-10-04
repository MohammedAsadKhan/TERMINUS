# ruff: noqa: F811
# pyright: basic, reportPrivateUsage=false, reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportAny=false, reportExplicitAny=false, reportMissingTypeArgument=false
"""O05 WP2: eight core role plans, factory and deployable handlers."""

from __future__ import annotations

import json

import pytest

from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.scheduler_cli import load_handlers
from terminus.orchestration.specialists import deploy
from terminus.orchestration.specialists.factory import build_specialist_handlers
from terminus.orchestration.specialists.roles import ROLE_SPECS
from terminus.orchestration.specialists.runtime import MAX_TOOL_CALLS, SpecialistDeps
from terminus.toolkit.catalog import CORE_ROLES, load_catalog
from tests.test_investigation_read_service import setup as read_setup  # noqa: F401
from tests.test_specialist_runtime import deps_for, job_context, parse

CATALOG = load_catalog()
BUNDLES = {b.role: set(b.tool_ids) for b in CATALOG.core_bundles}
TOOLS = {t.tool_id: t for t in CATALOG.tools}
ROLES = sorted(CORE_ROLES)
UNINSTALLED = {
    "network": {"network.connections", "network.dns"},
    "application_api": {"application.requests", "application.inventory"},
    "response_planner": {"response.eligibility"},
    "verification": {"verification.evaluate"},
    "evidence_reporting": {"reporting.incident_draft"},
}


def grantable(tool):
    return (
        tool.release == "1.0"
        and tool.effect in {"read", "local_analysis"}
        and tool.egress == "none"
        and tool.input_contract == "read_query"
    )


def grant_full_bundles(policies):
    """Admin grants every non-proposal bundle tool so absence is installation."""
    current = policies.get_policy("org", "incident")
    grants = {
        role: [t for t in ids if grantable(TOOLS[t])] for role, ids in BUNDLES.items()
    }
    policies.put_policy(
        "admin",
        "org",
        "incident",
        grants,
        current.connector_ids,
        expected_version=current.version,
    )


def test_exactly_the_eight_core_roles():
    assert set(ROLE_SPECS) == CORE_ROLES
    assert all(spec.role == role for role, spec in ROLE_SPECS.items())


@pytest.mark.parametrize("role", ROLES)
def test_plan_is_bounded_subset_of_bundle_without_dispatch(role):
    ids = [step.tool_id for step in ROLE_SPECS[role].plan]
    assert ids
    assert len(ids) <= MAX_TOOL_CALLS
    assert len(set(ids)) == len(ids)
    assert set(ids) <= BUNDLES[role]
    for tool_id in ids:
        assert TOOLS[tool_id].effect in {"read", "local_analysis"}
        assert tool_id not in {"response.wazuh_ip_block", "recovery.wazuh_ip_unblock"}
        assert tool_id != "response.propose"


def test_installed_today_plans_and_order():
    plan = {r: [s.tool_id for s in ROLE_SPECS[r].plan] for r in ROLES}
    assert plan["triage"] == ["incident.get", "alerts.search", "collection.coverage"]
    assert plan["identity"] == [
        "incident.get",
        "identity.auth_events",
        "collection.coverage",
    ]
    assert plan["endpoint"] == [
        "incident.get",
        "endpoint.agent",
        "alerts.search",
        "collection.coverage",
    ]
    for role in ("response_planner", "verification", "evidence_reporting"):
        assert plan[role][:2] == ["evidence.timeline", "evidence.validate_citations"]
        assert ROLE_SPECS[role].plan[1].cite_run_evidence
    assert "network.connections" in plan["network"]
    assert "application.requests" in plan["application_api"]


def test_queries_come_from_the_task_only(read_setup):
    make, _, _, _ = read_setup
    _, lease = make()
    for spec in ROLE_SPECS.values():
        for step in spec.plan:
            q = step.build_query(lease.task)
            assert q.resource_id in {"incident-ref", "endpoint-ref"}
            assert (q.end - q.start).total_seconds() <= 3600


def test_factory_builds_all_eight(read_setup):
    make, _, _, _ = read_setup
    service, _ = make()
    assert set(build_specialist_handlers(deps_for(service))) == CORE_ROLES


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ROLES)
async def test_each_role_runs_claimed_fixture_with_persisted_result(read_setup, role):
    make, policies, scheduler, _ = read_setup
    grant_full_bundles(policies)
    # Prior triage evidence so the evidence roles have a timeline to read.
    seed_service, seed_lease = make(role="triage")
    seeded = parse(
        await build_specialist_handlers(deps_for(seed_service))["triage"](
            job_context(scheduler, seed_lease)
        )
    )
    assert seeded.evidence_ids
    service, lease = make(role=role)
    out = await build_specialist_handlers(deps_for(service))[role](
        job_context(scheduler, lease)
    )
    _ = scheduler.complete(lease, out)
    stored = scheduler.records.get_agent_run("org", lease.run.run_id)
    result = parse(json.loads(json.dumps(stored.result)))
    assert result.role == role
    assert result.execution_mode == "tools_only"
    assert result.evidence_ids
    assert result.findings == ()  # tools-only: no invented findings
    for evidence_id in result.evidence_ids:
        assert scheduler.records.get_evidence("org", evidence_id).org_id == "org"
    planned = [s.tool_id for s in ROLE_SPECS[role].plan]
    assert {c.tool_id for c in result.tool_calls} <= set(planned)
    invoked = {i.tool_id for i in service.audit.list_invocations("org", lease.task_id)}
    assert invoked <= set(planned)
    absent = {g.tool_id for g in result.gaps if g.code == "tool_not_installed"}
    assert UNINSTALLED.get(role, set()) <= absent
    assert result.status == "partial"


@pytest.mark.asyncio
async def test_role_without_telemetry_is_insufficient(read_setup):
    make, policies, scheduler, _ = read_setup
    grant_full_bundles(policies)
    service, lease = make(role="evidence_reporting")
    result = parse(
        await build_specialist_handlers(deps_for(service))["evidence_reporting"](
            job_context(scheduler, lease)
        )
    )
    assert result.status == "insufficient_telemetry"
    assert result.evidence_ids == ()
    assert result.findings == ()
    assert result.gaps


@pytest.mark.asyncio
async def test_wrong_role_task_is_rejected(read_setup):
    make, _, scheduler, requests = read_setup
    service, lease = make(role="triage")
    result = parse(
        await build_specialist_handlers(deps_for(service))["identity"](
            job_context(scheduler, lease)
        )
    )
    assert result.status == "error"
    assert result.gaps[0].code == "role_mismatch"
    assert requests == []


# ---- deployment ------------------------------------------------------------


@pytest.fixture(autouse=True)
def clean_deploy():
    deploy.reset_deployment()
    deploy.configure_connectors(None)
    yield
    deploy.reset_deployment()
    deploy.configure_connectors(None)


def test_load_handlers_accepts_all_eight_and_coordination_coexists(read_setup):
    _, _, scheduler, _ = read_setup
    module = "terminus.orchestration.specialists.deploy"
    handlers = load_handlers([f"{role}={module}:{role}" for role in ROLES])
    assert set(handlers) == CORE_ROLES
    builtins = CoordinationService(scheduler.db).handlers()
    assert not handlers.keys() & builtins.keys()


@pytest.mark.asyncio
async def test_unconfigured_deployment_fails_closed(read_setup, monkeypatch):
    make, _, scheduler, requests = read_setup
    _, lease = make()
    monkeypatch.delenv(deploy.DATABASE_ENV, raising=False)
    monkeypatch.delenv(deploy.ACTOR_ENV, raising=False)
    with pytest.raises(deploy.SpecialistDeploymentError, match="TERMINUS_SPECIALIST"):
        _ = await deploy.triage(job_context(scheduler, lease))
    monkeypatch.setenv(deploy.DATABASE_ENV, "unused.db")
    with pytest.raises(deploy.SpecialistDeploymentError, match=deploy.ACTOR_ENV):
        _ = await deploy.triage(job_context(scheduler, lease))
    assert requests == []


@pytest.mark.asyncio
async def test_configured_deployment_runs_store_only_with_explicit_gaps(
    read_setup, monkeypatch
):
    make, _, scheduler, requests = read_setup
    _, lease = make()
    env = {deploy.DATABASE_ENV: scheduler.db.db_path, deploy.ACTOR_ENV: "member"}
    deps = deploy.build_deployment_deps(env, clock=scheduler.clock)
    result = parse(
        await build_specialist_handlers(deps)["triage"](job_context(scheduler, lease))
    )
    assert result.execution_mode == "tools_only"
    assert result.tool_calls[0].tool_id == "incident.get"
    assert result.evidence_ids
    assert result.status == "partial"
    assert result.findings == ()
    assert {g.tool_id for g in result.gaps} >= {"alerts.search", "collection.coverage"}
    assert requests == []  # no connector credentials were invented


@pytest.mark.asyncio
async def test_deploy_function_uses_cached_env_configuration(read_setup, monkeypatch):
    make, _, scheduler, requests = read_setup
    _, lease = make()
    monkeypatch.setenv(deploy.DATABASE_ENV, scheduler.db.db_path)
    monkeypatch.setenv(deploy.ACTOR_ENV, "member")
    result = parse(await deploy.triage(job_context(scheduler, lease)))
    assert result.role == "triage"
    assert result.execution_mode == "tools_only"
    assert result.findings == ()
    assert result.status in {"partial", "insufficient_telemetry"}
    assert result.gaps  # never a clean verdict without real readers
    assert deploy._handlers() is deploy._handlers()
    assert requests == []


def test_resolver_fails_closed_for_unknown_org(read_setup):
    _, _, scheduler, _ = read_setup
    deps = deploy.build_deployment_deps(
        {deploy.DATABASE_ENV: scheduler.db.db_path, deploy.ACTOR_ENV: "member"}
    )
    assert isinstance(deps, SpecialistDeps)
    assert deps.routing is None
    assert deps.client_for is None
    assert deps.read_service_for("unknown-org") is None
    service = deps.read_service_for("org")
    assert service is not None
    assert service.org_id == "org"
    assert service.manager is None
    assert service.indexer is None
    assert deps.read_service_for("org") is service
