# ruff: noqa: F811
# pyright: basic, reportPrivateUsage=false, reportMissingParameterType=false, reportUnknownParameterType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportUnknownMemberType=false, reportAny=false, reportExplicitAny=false, reportMissingTypeArgument=false
"""O05 wiring: production bridge, WAITING_SPECIALIST, automatic resume, incident window."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import terminus.pipeline.workflow_engine as we
from terminus.models import (
    RunOutcome,
    SiemAlert,
    Workflow,
    WorkflowEdge,
    WorkflowNode,
    WorkflowRunStatus,
)
from terminus.orchestration.specialists import deploy
from terminus.orchestration.specialists.factory import build_specialist_handlers
from terminus.orchestration.specialists.roles import ROLE_SPECS
from terminus.pipeline.specialist_bridge import (
    DATABASE_ENV,
    ROLES_ENV,
    SpecialistBridge,
    specialist_bridge_from_environ,
)
from terminus.pipeline.sweeper import (
    MAX_SPECIALIST_RESUMES_PER_PASS,
    resume_ready_specialist_runs,
    run_sweeper_cycle,
)
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database
from terminus.storage.repositories import SqliteAlertClaimRepository
from tests.test_investigation_read_service import NOW
from tests.test_investigation_read_service import setup as read_setup  # noqa: F401
from tests.test_scheduler_runtime import _admit, _runtime, _status, _stop
from tests.test_scheduler_runtime import store as sched_store  # noqa: F401
from tests.test_specialist_runtime import job_context, parse


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(str(tmp_path / "wiring.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("a", "b"):
        database.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
        database.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (f"inc-{org}", org, f"alert-{org}", "high", "high", "F", "[]", "standard", now),
        )
    yield database
    database.close()


def _workflow(role: str = "endpoint") -> Workflow:
    return Workflow(
        id="wf-ai",
        name="AI",
        nodes=[
            WorkflowNode(id="t", type="trigger_wazuh", config={"min_level": 1}),
            WorkflowNode(id="ai", type="agent_llm", config={"role": role}),
        ],
        edges=[WorkflowEdge(id="e", source="t", target="ai", source_handle="default")],
    )


def _alert(alert_id: str = "al") -> SiemAlert:
    return SiemAlert(id=alert_id, rule_id=1, level=12, description="d", location="l", agent_name="h")


def _finish_all(bridge: SpecialistBridge, role: str = "endpoint", count: int = 1) -> None:
    store = bridge.scheduler
    assert store.acquire_coordinator("owner", lease_seconds=300)
    for _ in range(count):
        lease = store.claim_next("owner", "worker", [role], lease_seconds=300)
        assert lease is not None
        store.complete(lease, {"status": "completed", "role": role, "evidence_ids": ["ev-1"]})


async def _cycle(engine: WorkflowEngine, claim_repo=None) -> dict[str, int]:
    return await run_sweeper_cycle(
        run_repo=engine.run_repo,
        approval_repo=engine.approval_repo,
        workflow_engine=engine,
        claim_repo=claim_repo,
    )


# ---- configuration signal ---------------------------------------------------


def test_bridge_absent_unless_roles_declared(db):
    assert specialist_bridge_from_environ(db, {}) is None
    assert specialist_bridge_from_environ(db, {ROLES_ENV: "  , "}) is None
    assert specialist_bridge_from_environ(db, {ROLES_ENV: "wizard"}) is None
    # Handler-process variables alone never enable the bridge.
    assert specialist_bridge_from_environ(db, {DATABASE_ENV: db.db_path}) is None


def test_bridge_handler_roles_come_from_declaration(db):
    bridge = specialist_bridge_from_environ(db, {ROLES_ENV: "triage, network ,bogus"})
    assert bridge is not None
    assert bridge.handler_roles == frozenset({"triage", "network"})


def test_bridge_refuses_database_mismatch(db, tmp_path):
    other = str(tmp_path / "other.db")
    assert specialist_bridge_from_environ(db, {ROLES_ENV: "triage", DATABASE_ENV: other}) is None
    same = specialist_bridge_from_environ(db, {ROLES_ENV: "triage", DATABASE_ENV: db.db_path})
    assert same is not None


def test_server_deps_builds_bridge_only_when_declared(db, monkeypatch):
    from terminus.server import deps

    monkeypatch.setattr(Database, "get_instance", classmethod(lambda cls, p="x": db))
    deps._BRIDGE_CACHE.clear()
    monkeypatch.delenv(ROLES_ENV, raising=False)
    monkeypatch.delenv(DATABASE_ENV, raising=False)
    assert deps._specialist_bridge() is None
    assert deps.get_pipeline_runner(deps.get_settings()).workflow_engine.specialist_bridge is None
    monkeypatch.setenv(ROLES_ENV, "endpoint")
    bridge = deps._specialist_bridge()
    assert bridge is not None
    assert bridge.handler_roles == frozenset({"endpoint"})
    assert deps._specialist_bridge() is bridge  # cached, no per-request rebuild
    runner = deps.get_pipeline_runner(deps.get_settings())
    assert runner.workflow_engine.specialist_bridge is bridge
    deps._BRIDGE_CACHE.clear()


@pytest.mark.asyncio
async def test_unconfigured_keeps_exact_legacy_path(db, monkeypatch):
    class Legacy:
        def __init__(self, llm):
            pass

        async def investigate(self, alert, org_id, persona_prompt=""):
            from tests.test_specialist_bridge import _FakeAgent

            return await _FakeAgent(None).investigate(alert, org_id, persona_prompt)

    monkeypatch.setattr(we, "InvestigationAgent", Legacy)
    engine = WorkflowEngine(db=db, specialist_bridge=specialist_bridge_from_environ(db, {}))
    deployment = SimpleNamespace(agent=SimpleNamespace(llm=object()), ticket_store=object())
    ctx = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", deployment=deployment
    )
    assert ctx.node_outputs["ai"]["legacy_unrecorded"] is True
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0
    assert (await _cycle(engine))["specialist_resumes"] == 0


@pytest.mark.asyncio
async def test_role_without_deployed_handler_is_not_executed_not_waiting(db):
    bridge = specialist_bridge_from_environ(db, {ROLES_ENV: "network"})
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    ctx = await engine.execute_workflow(
        workflow=_workflow("endpoint"), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert ctx.node_statuses["ai"] == "NOT_EXECUTED"
    assert ctx.status != "WAITING_SPECIALIST"
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0


# ---- WAITING_SPECIALIST status ----------------------------------------------


def test_status_enums_include_waiting_specialist():
    assert WorkflowRunStatus.WAITING_SPECIALIST.value == "WAITING_SPECIALIST"
    assert RunOutcome.WAITING_SPECIALIST.value == "WAITING_SPECIALIST"


@pytest.mark.asyncio
async def test_waiting_run_is_listed_and_not_marked_completed(db):
    engine = WorkflowEngine(db=db, specialist_bridge=SpecialistBridge(db))
    ctx = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    row = engine.run_repo.list_runs_for_org("a")[0]
    assert row["status"] == WorkflowRunStatus.WAITING_SPECIALIST
    assert row["outcome"] == RunOutcome.WAITING_SPECIALIST
    assert not row.get("completed_at")
    assert [r["run_id"] for r in engine.run_repo.list_waiting_specialist_runs()] == [ctx.run_id]
    # Not swept as a stale RUNNING run either.
    assert engine.run_repo.get_stale_running_runs(max_heartbeat_age_seconds=0) == []


# ---- automatic resume -------------------------------------------------------


@pytest.mark.asyncio
async def test_sweeper_resumes_only_after_task_is_terminal_and_is_idempotent(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    claims = SqliteAlertClaimRepository(db)
    claims.claim_alert("a", "al")
    ctx = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert ctx.status == "WAITING_SPECIALIST"

    assert (await _cycle(engine, claims))["specialist_resumes"] == 0
    assert engine.run_repo.get_run("a", ctx.run_id)["status"] == "WAITING_SPECIALIST"

    _finish_all(bridge)
    assert (await _cycle(engine, claims))["specialist_resumes"] == 1
    run = engine.run_repo.get_run("a", ctx.run_id)
    assert run["status"] == "COMPLETED"
    assert run["outcome"] == "HANDLED"
    assert run["completed_at"]
    claim = claims.get_claim("a", "al")
    assert (claim["status"], claim["outcome"]) == ("COMPLETED", "HANDLED")
    assert len(bridge.records.list_tasks("a", incident_id="inc-a")) == 1
    # Second pass does nothing.
    assert (await _cycle(engine, claims))["specialist_resumes"] == 0


@pytest.mark.asyncio
async def test_concurrent_resume_claim_is_exclusive(db):
    engine = WorkflowEngine(db=db, specialist_bridge=SpecialistBridge(db))
    ctx = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert engine.run_repo.claim_waiting_specialist_run("a", ctx.run_id) is True
    assert engine.run_repo.claim_waiting_specialist_run("a", ctx.run_id) is False
    assert engine.run_repo.claim_waiting_specialist_run("b", ctx.run_id) is False


@pytest.mark.asyncio
async def test_failed_specialist_task_also_resumes_without_fabricating(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    ctx = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    store = bridge.scheduler
    assert store.acquire_coordinator("owner", lease_seconds=300)
    lease = store.claim_next("owner", "worker", ["endpoint"], lease_seconds=300)
    assert lease is not None
    store.fail(lease, "boom", retryable=False)
    assert (await _cycle(engine))["specialist_resumes"] == 1
    done = engine.run_repo.get_run("a", ctx.run_id)
    assert done["status"] == "FAILED"
    nodes = {n["node_id"]: n for n in engine.run_repo.get_node_runs("a", ctx.run_id)}
    assert "verdict" not in nodes["ai"]["outputs"]


@pytest.mark.asyncio
async def test_resume_is_tenant_safe(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    waiting = await engine.execute_workflow(
        workflow=_workflow(), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    # Another tenant has a finished task under the very same workflow key.
    foreign = bridge.request(
        org_id="b",
        incident_id="inc-b",
        run_id=waiting.run_id,
        node_id="ai",
        workflow_id="wf-ai",
        config={"role": "endpoint"},
    )
    assert foreign.state == "waiting"
    store = bridge.scheduler
    assert store.acquire_coordinator("owner", lease_seconds=300)
    leases = [store.claim_next("owner", f"w{i}", ["endpoint"], lease_seconds=300) for i in range(2)]
    assert all(leases)
    for lease in leases:
        if lease.task.org_id == "b":  # only the foreign tenant's task finishes
            store.complete(lease, {"status": "completed"})
    assert bridge.task_status("b", waiting.run_id, "ai") == "completed"
    assert bridge.task_status("a", waiting.run_id, "ai") == "running"
    assert (await _cycle(engine))["specialist_resumes"] == 0
    assert engine.run_repo.get_run("a", waiting.run_id)["status"] == "WAITING_SPECIALIST"


@pytest.mark.asyncio
async def test_resume_pass_is_bounded_and_drains_over_passes(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    total = MAX_SPECIALIST_RESUMES_PER_PASS + 3
    for i in range(total):
        ctx = await engine.execute_workflow(
            workflow=_workflow(), alert=_alert(f"al-{i}"), org_id="a", incident_id="inc-a"
        )
        assert ctx.status == "WAITING_SPECIALIST"
    _finish_all(bridge, count=total)
    first = await resume_ready_specialist_runs(engine.run_repo, engine)
    assert first == MAX_SPECIALIST_RESUMES_PER_PASS
    second = await resume_ready_specialist_runs(engine.run_repo, engine)
    assert second == 3
    assert engine.run_repo.list_waiting_specialist_runs() == []


@pytest.mark.asyncio
async def test_unready_runs_rotate_so_they_cannot_starve_ready_ones(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    ctxs = [
        await engine.execute_workflow(
            workflow=_workflow(), alert=_alert(f"al-{i}"), org_id="a", incident_id="inc-a"
        )
        for i in range(3)
    ]
    before = {r["run_id"]: r["heartbeat_at"] for r in engine.run_repo.list_waiting_specialist_runs()}
    assert await resume_ready_specialist_runs(engine.run_repo, engine) == 0
    after = {r["run_id"]: r["heartbeat_at"] for r in engine.run_repo.list_waiting_specialist_runs()}
    assert set(before) == set(after) == {c.run_id for c in ctxs}
    assert all(after[k] >= before[k] for k in before)  # checked runs move to the back


# ---- incident-anchored window -----------------------------------------------


@pytest.mark.asyncio
async def test_old_alert_gets_valid_incident_window(read_setup):
    make, _, scheduler, _ = read_setup
    old = NOW - timedelta(hours=6)
    scheduler.db.execute(
        "UPDATE incidents SET raw_payload_json=? WHERE ticket_id='incident'",
        (json.dumps({"id": "alert-1", "timestamp": old.isoformat(), "full_log": "old"}),),
    )
    env = {deploy.DATABASE_ENV: scheduler.db.db_path, deploy.ACTOR_ENV: "member"}
    deps = deploy.build_deployment_deps(env, clock=scheduler.clock)
    assert deps.incident_time_for is not None
    assert deps.incident_time_for("org", "incident") == old
    assert deps.incident_time_for("other-org", "incident") is None  # tenant-scoped

    _, lease = make()
    result = parse(
        await build_specialist_handlers(deps)["triage"](job_context(scheduler, lease))
    )
    first = result.tool_calls[0]
    assert first.tool_id == "incident.get"
    assert first.status == "ok"
    assert first.evidence_count == 1
    assert "incident_source_outside_window" not in {g.detail for g in result.gaps}


@pytest.mark.asyncio
async def test_without_incident_time_old_alert_is_outside_window(read_setup):
    make, _, scheduler, _ = read_setup
    scheduler.db.execute(
        "UPDATE incidents SET raw_payload_json=? WHERE ticket_id='incident'",
        (
            json.dumps(
                {"id": "alert-1", "timestamp": (NOW - timedelta(hours=6)).isoformat(), "full_log": "x"}
            ),
        ),
    )
    env = {deploy.DATABASE_ENV: scheduler.db.db_path, deploy.ACTOR_ENV: "member"}
    deps = deploy.build_deployment_deps(env, clock=scheduler.clock)
    deps = type(deps)(
        read_service_for=deps.read_service_for, actor_user_id=deps.actor_user_id
    )  # legacy: no resolver
    _, lease = make()
    result = parse(
        await build_specialist_handlers(deps)["triage"](job_context(scheduler, lease))
    )
    assert result.tool_calls[0].status != "ok"


def test_builder_window_is_clamped_to_one_hour_around_anchor(read_setup):
    from terminus.orchestration.specialists.runtime import QueryContext

    make, _, _, _ = read_setup
    _, lease = make()
    anchor = NOW - timedelta(days=30)
    for spec in ROLE_SPECS.values():
        for step in spec.plan:
            q = step.build_query(lease.task, QueryContext(anchor))
            assert q.start <= anchor <= q.end
            assert (q.end - q.start).total_seconds() <= 3600


def test_resolver_ignores_unparseable_and_naive_timestamps(read_setup):
    _, _, scheduler, _ = read_setup
    env = {deploy.DATABASE_ENV: scheduler.db.db_path, deploy.ACTOR_ENV: "member"}
    deps = deploy.build_deployment_deps(env)
    assert deps.incident_time_for is not None
    scheduler.db.execute(
        "UPDATE incidents SET raw_payload_json=? WHERE ticket_id='incident'",
        (json.dumps({"timestamp": "garbage"}),),
    )
    assert deps.incident_time_for("org", "incident") is None
    scheduler.db.execute(
        "UPDATE incidents SET raw_payload_json=? WHERE ticket_id='incident'",
        (json.dumps({"timestamp": "2026-01-01T00:00:00"}),),
    )
    assert deps.incident_time_for("org", "incident") == datetime(2026, 1, 1, tzinfo=UTC)


# ---- non-retryable missing configuration ------------------------------------


def test_deployment_error_is_declared_non_retryable():
    assert deploy.SpecialistDeploymentError.retryable is False


@pytest.mark.asyncio
async def test_missing_configuration_fails_terminally_without_consuming_retries(sched_store):
    task = _admit(sched_store, attempts=3)
    calls = 0

    async def handler(_context):
        nonlocal calls
        calls += 1
        raise deploy.SpecialistDeploymentError("Specialist deployment is not configured")

    runtime = _runtime(sched_store, {"analyst": handler})
    runner = asyncio.create_task(runtime.run())
    try:
        await _status(sched_store, task, "failed")
        await asyncio.sleep(0.1)
    finally:
        await _stop(runtime, runner)
    assert calls == 1
    assert sched_store.get_job(task.org_id, task.task_id).attempt == 1
