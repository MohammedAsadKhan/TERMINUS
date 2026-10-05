"""Workflow AI nodes report recorded specialist runs only; nothing is fabricated."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from terminus.models import SiemAlert, Workflow, WorkflowEdge, WorkflowNode
from terminus.pipeline.specialist_bridge import SpecialistBridge, resolve_role
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database

ROLE_CFG = {"role": "endpoint"}


@pytest.fixture
def db(tmp_path: Path) -> Iterator[Database]:
    database = Database(str(tmp_path / "bridge.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("a", "b"):
        database.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
        database.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (f"inc-{org}", org, f"alert-{org}", "high", "high", "Fixture", "[]", "standard", now),
        )
    yield database
    database.close()


def _request(bridge, *, org="a", incident="inc-a", run="r1", node="n1", cfg=ROLE_CFG):
    return bridge.request(
        org_id=org, incident_id=incident, run_id=run, node_id=node, workflow_id="wf", config=cfg
    )


def _complete(bridge: SpecialistBridge, org: str, task_id: str, result: object) -> None:
    store = bridge.scheduler
    assert store.acquire_coordinator("owner", lease_seconds=300)
    lease = store.claim_next("owner", "worker", ["endpoint"], lease_seconds=300)
    assert lease is not None
    assert lease.task.task_id == task_id
    store.complete(lease, result)  # type: ignore[arg-type]


def _evidence(bridge: SpecialistBridge, org: str, task_id: str):
    return bridge.records.create_evidence(
        org, task_id, "endpoint.logs", datetime.now(UTC),
        content={"event": "suspicious process recorded"},
    )


def test_waits_then_returns_recorded_result_unmodified(db: Database) -> None:
    bridge = SpecialistBridge(db, handler_roles={"endpoint"})
    first = _request(bridge)
    assert first.state == "waiting"
    assert first.task_id
    assert first.run_id is None
    assert "verdict" not in first.to_output()

    ids = [_evidence(bridge, "a", first.task_id).evidence_id for _ in range(2)]
    recorded = {"status": "completed", "role": "endpoint", "evidence_ids": ids, "findings": []}
    _complete(bridge, "a", first.task_id, recorded)
    done = _request(bridge)
    assert done.state == "completed"
    assert done.task_id == first.task_id
    assert done.result == recorded
    assert done.evidence_ids == tuple(ids)
    out = done.to_output()
    assert out["recorded_run"] is True
    assert out["run_id"]
    assert "verdict" not in out


@pytest.mark.parametrize(
    "cfg",
    [
        None,
        {},
        {"role": "wizard"},
        {"agent_id": "legacy-agent-7"},
        {"role": "endpoint", "agent_id": "network"},
        {"role": "main_orchestrator"},
        {"role": 5},
    ],
)
def test_unknown_or_absent_role_is_unresolved(db: Database, cfg) -> None:
    bridge = SpecialistBridge(db)
    out = _request(bridge, cfg=cfg)
    assert out.state == "unresolved_agent"
    assert out.task_id is None
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0


def test_agent_id_resolves_only_to_a_core_role() -> None:
    assert resolve_role({"agent_id": "network"}) == "network"
    assert resolve_role({"role": "network", "agent_id": "network"}) == "network"
    assert resolve_role({"agent_id": "triage-bot"}) is None


def test_no_handler_no_incident_missing_incident_not_executed(db: Database) -> None:
    no_handler = _request(SpecialistBridge(db, handler_roles={"network"}))
    assert no_handler.state == "not_executed"
    assert "handler" in (no_handler.gap or "")
    bridge = SpecialistBridge(db)
    assert _request(bridge, incident=None).state == "not_executed"
    missing = _request(bridge, incident="nope")
    assert missing.state == "not_executed"
    assert missing.gap
    for outcome in (no_handler, missing):
        assert outcome.result is None
        assert "verdict" not in outcome.to_output()
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0


def test_idempotency_key_prevents_duplicate_task(db: Database) -> None:
    bridge = SpecialistBridge(db)
    first, second = _request(bridge), _request(bridge)
    assert first.task_id == second.task_id
    rows = db.fetchall("SELECT idempotency_key FROM orchestration_tasks")
    assert [r["idempotency_key"] for r in rows] == ["workflow:r1:n1"]
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_scheduler_jobs")["c"] == 1
    other = _request(bridge, node="n2")
    assert other.task_id != first.task_id


def test_tenant_isolation(db: Database) -> None:
    bridge = SpecialistBridge(db)
    foreign = _request(bridge, org="a", incident="inc-b")
    assert foreign.state == "not_executed"
    mine = _request(bridge, org="b", incident="inc-b")
    assert mine.state == "waiting"
    task = bridge.records.get_task("b", mine.task_id or "")
    assert task.org_id == "b"
    assert task.incident_id == "inc-b"
    # Same run/node key in another tenant is a distinct task.
    other = _request(bridge, org="a", incident="inc-a")
    assert other.task_id != mine.task_id


def test_node_config_cannot_select_org_or_incident(db: Database) -> None:
    bridge = SpecialistBridge(db)
    hostile = {"role": "endpoint", "org_id": "b", "incident_id": "inc-b", "tenant": "b"}
    out = _request(bridge, org="a", incident="inc-a", cfg=hostile)
    assert out.state == "waiting"
    task = bridge.records.get_task("a", out.task_id or "")
    assert (task.org_id, task.incident_id) == ("a", "inc-a")
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks WHERE org_id='b'")["c"] == 0


def _workflow(cfg: dict) -> Workflow:
    return Workflow(
        id="wf-ai",
        name="AI",
        nodes=[
            WorkflowNode(id="t", type="trigger_wazuh", config={"min_level": 1}),
            WorkflowNode(id="ai", type="agent_llm", config=cfg),
        ],
        edges=[WorkflowEdge(id="e", source="t", target="ai", source_handle="default")],
    )


def _alert() -> SiemAlert:
    return SiemAlert(id="alert-a", rule_id=1, level=12, description="d", location="l", agent_name="h")


def _report(alert):
    from terminus.models import Confidence, Evidence, InvestigationReport, PolicyResult, Severity, Tier, Verdict

    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(alert_id=alert.id, tier=Tier.TRIAGE, should_investigate=True, reason="r"),
        verdict=Verdict(severity=Severity.LOW, confidence=Confidence.LOW, summary="legacy", recommended_actions=[]),
        evidence=Evidence(alert=alert, agent_name=alert.agent_name, threat_intel="", context_notes=""),
    )


@pytest.mark.anyio
async def test_engine_dry_run_is_labeled_simulated_without_verdict(db: Database) -> None:
    ctx = await WorkflowEngine(db=db).execute_workflow(
        workflow=_workflow({"role": "endpoint", "persona_instructions": "p"}),
        alert=_alert(),
        org_id="a",
        dry_run=True,
    )
    out = ctx.node_outputs["ai"]
    assert ctx.node_statuses["ai"] == "SUCCESS"
    assert out["simulated"] is True
    assert out["dry_run"] is True
    assert out["recorded_run"] is False
    assert out["executed"] is False
    assert "verdict" not in out
    assert "[Dry-Run]" not in ctx.report.verdict.summary
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0


class _FakeAgent:
    def __init__(self, llm: object) -> None:
        self.llm = llm

    async def investigate(self, alert, org_id, persona_prompt=""):
        from terminus.models import Confidence, Evidence, InvestigationReport, PolicyResult, Severity, Tier, Verdict

        return InvestigationReport(
            alert_id=alert.id,
            policy=PolicyResult(alert_id=alert.id, tier=Tier.TRIAGE, should_investigate=True, reason="r"),
            verdict=Verdict(severity=Severity.LOW, confidence=Confidence.LOW, summary="legacy", recommended_actions=[]),
            evidence=Evidence(alert=alert, agent_name=alert.agent_name, threat_intel="", context_notes=""),
        )


@pytest.mark.anyio
async def test_engine_live_without_bridge_uses_labeled_legacy_path(db: Database, monkeypatch) -> None:
    from types import SimpleNamespace

    import terminus.pipeline.workflow_engine as we

    monkeypatch.setattr(we, "InvestigationAgent", _FakeAgent)
    deployment = SimpleNamespace(agent=SimpleNamespace(llm=object()), ticket_store=object())
    ctx = await WorkflowEngine(db=db).execute_workflow(
        workflow=_workflow({"role": "endpoint"}), alert=_alert(), org_id="a", deployment=deployment
    )
    assert ctx.node_statuses["ai"] == "SUCCESS"
    assert ctx.node_outputs["ai"]["legacy_unrecorded"] is True
    assert ctx.report.verdict.summary == "legacy"
    assert db.fetchone("SELECT COUNT(*) AS c FROM orchestration_tasks")["c"] == 0


@pytest.mark.anyio
async def test_engine_with_bridge_never_calls_legacy_agent(db: Database, monkeypatch) -> None:
    import terminus.pipeline.workflow_engine as we

    def boom(*_a, **_k):
        raise AssertionError("legacy agent must not run")

    monkeypatch.setattr(we, "InvestigationAgent", boom)
    engine = WorkflowEngine(db=db, specialist_bridge=SpecialistBridge(db, handler_roles={"network"}))
    ctx = await engine.execute_workflow(
        workflow=_workflow({"role": "endpoint"}), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert ctx.node_statuses["ai"] == "NOT_EXECUTED"
    assert "verdict" not in ctx.node_outputs["ai"]


@pytest.mark.anyio
async def test_waiting_run_is_not_completed_and_resumes_with_recorded_result(db: Database) -> None:
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    ctx = await engine.execute_workflow(
        workflow=_workflow({"role": "endpoint"}), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert ctx.status == "WAITING_SPECIALIST"
    assert ctx.outcome == "WAITING_SPECIALIST"

    still = await engine.resume_run(ctx.run_id, "a")
    assert still is not None
    assert still.node_statuses["ai"] == "WAITING_SPECIALIST"
    assert still.status == "WAITING_SPECIALIST"

    task = bridge.records.list_tasks("a", incident_id="inc-a")[0]
    evidence = _evidence(bridge, "a", task.task_id)
    recorded = {"status": "completed", "role": "endpoint", "evidence_ids": [evidence.evidence_id]}
    _complete(bridge, "a", task.task_id, recorded)
    done = await engine.resume_run(ctx.run_id, "a")
    assert done is not None
    assert done.node_statuses["ai"] == "SUCCESS"
    assert done.node_outputs["ai"]["result"] == recorded
    assert done.node_outputs["ai"]["evidence_ids"] == [evidence.evidence_id]
    assert done.status == "COMPLETED"
    assert len(bridge.records.list_tasks("a", incident_id="inc-a")) == 1


@pytest.mark.anyio
async def test_engine_live_waits_then_succeeds_with_recorded_result(db: Database) -> None:
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    workflow = _workflow({"role": "endpoint"})
    ctx = await engine.execute_workflow(
        workflow=workflow, alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert ctx.node_statuses["ai"] == "WAITING_SPECIALIST"
    assert ctx.node_outputs["ai"]["specialist_state"] == "waiting"
    task = bridge.records.list_tasks("a", incident_id="inc-a")[0]
    assert task.idempotency_key == f"workflow:{ctx.run_id}:ai"

    unresolved = await engine.execute_workflow(
        workflow=_workflow({"agent_id": "ghost"}), alert=_alert(), org_id="a", incident_id="inc-a"
    )
    assert unresolved.node_statuses["ai"] == "UNRESOLVED_AGENT"
    assert unresolved.status == "FAILED"
