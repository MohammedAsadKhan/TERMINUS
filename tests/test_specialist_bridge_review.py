# ruff: noqa: F811
"""Fail-closed specialist continuation and durable, cited report integration."""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from terminus.models import Confidence, Severity, WorkflowEdge, WorkflowNode
from terminus.pipeline.specialist_bridge import SpecialistBridge
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.repositories import SqliteIncidentRepository
from tests.test_specialist_bridge import (
    _FakeAgent,
    _alert,
    _complete,
    _evidence,
    _request,
    _workflow,
    db,  # noqa: F401
)


def _gated_workflow():
    workflow = _workflow({"role": "endpoint"})
    workflow.nodes.extend(
        [
            WorkflowNode(
                id="gate",
                type="condition_severity",
                config={"min_verdict_severity": "high"},
            ),
            WorkflowNode(id="notify", type="tool_slack"),
            WorkflowNode(id="ticket", type="tool_jira"),
            WorkflowNode(id="error", type="trigger_wazuh"),
        ]
    )
    workflow.edges.extend(
        [
            WorkflowEdge(id="default", source="ai", target="gate"),
            WorkflowEdge(
                id="severity", source="gate", target="notify", source_handle="true"
            ),
            WorkflowEdge(id="ticket", source="ai", target="ticket"),
            WorkflowEdge(
                id="error", source="ai", target="error", source_handle="on_error"
            ),
        ]
    )
    return workflow


async def _base_report(alert):
    report = await _FakeAgent(None).investigate(alert, "a")
    return dataclasses.replace(
        report,
        verdict=report.verdict.model_copy(
            update={
                "severity": Severity.HIGH,
                "confidence": Confidence.MEDIUM,
                "summary": "Existing assessed incident",
                "recommended_actions": ["Review host"],
            }
        ),
    )


@pytest.mark.asyncio
async def test_not_executed_blocks_default_side_effects_and_routes_on_error(db):
    bridge = SpecialistBridge(db, handler_roles={"network"})
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    deployment = SimpleNamespace(
        notifier=SimpleNamespace(notify=AsyncMock()),
        ticket_store=SimpleNamespace(create_ticket=AsyncMock()),
    )
    ctx = await engine.execute_workflow(
        _gated_workflow(),
        _alert(),
        await _base_report(_alert()),
        "a",
        deployment=deployment,
        incident_id="inc-a",
    )
    assert ctx.node_statuses["ai"] == "NOT_EXECUTED"
    assert ctx.status == "FAILED"
    assert ctx.outcome == "FAILED_BEFORE_SIDE_EFFECTS"
    assert ctx.node_statuses["error"] == "SUCCESS"
    assert all(ctx.node_statuses[n] == "SKIPPED" for n in ("gate", "notify", "ticket"))
    deployment.notifier.notify.assert_not_awaited()
    deployment.ticket_store.create_ticket.assert_not_awaited()
    assert not ctx.side_effects_executed
    assert engine.run_repo.get_run("a", ctx.run_id)["status"] == "FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["partial", "insufficient_telemetry", "error"])
async def test_scheduler_completed_payload_gaps_do_not_enable_default_actions(
    db, status
):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    deployment = SimpleNamespace(
        notifier=SimpleNamespace(notify=AsyncMock()),
        ticket_store=SimpleNamespace(create_ticket=AsyncMock()),
    )
    waiting = await engine.execute_workflow(
        _gated_workflow(),
        _alert(),
        await _base_report(_alert()),
        "a",
        deployment=deployment,
        incident_id="inc-a",
    )
    task = bridge.records.list_tasks("a", incident_id="inc-a")[0]
    evidence = _evidence(bridge, "a", task.task_id)
    findings = (
        [{"claim": "Observed process", "evidence_ids": [evidence.evidence_id]}]
        if status == "partial"
        else []
    )
    result = {
        "status": status,
        "role": "endpoint",
        "evidence_ids": [evidence.evidence_id],
        "findings": findings,
        "gaps": [
            {"code": "service_not_configured", "detail": "endpoint telemetry missing"}
        ],
    }
    _complete(bridge, "a", task.task_id, result)
    done = await engine.resume_run(waiting.run_id, "a", deployment=deployment)
    assert done is not None
    assert done.status == "FAILED"
    assert done.node_statuses["ai"] == "FAILED"
    assert done.node_statuses["error"] == "SUCCESS"
    assert all(done.node_statuses[n] == "SKIPPED" for n in ("gate", "notify", "ticket"))
    deployment.notifier.notify.assert_not_awaited()
    deployment.ticket_store.create_ticket.assert_not_awaited()
    assert "endpoint telemetry missing" in done.report.evidence.context_notes
    assert done.report.verdict.severity == Severity.HIGH
    assert done.report.verdict.recommended_actions == ["Review host"]
    if status == "partial":
        assert "Observed process" in done.report.verdict.summary


@pytest.mark.parametrize(
    "bad",
    [
        "unknown_evidence",
        "foreign_incident",
        "foreign_tenant",
        "role",
        "uncited",
        "extra_assessment",
        "empty",
        "invalid_schema",
    ],
)
def test_invalid_recorded_result_never_becomes_completed(db, bad):
    bridge = SpecialistBridge(db)
    first = _request(bridge)
    assert first.task_id
    evidence = _evidence(bridge, "a", first.task_id)
    result = {
        "status": "completed",
        "role": "endpoint",
        "evidence_ids": [evidence.evidence_id],
        "findings": [
            {"claim": "Observed process", "evidence_ids": [evidence.evidence_id]}
        ],
    }
    if bad == "unknown_evidence":
        result["evidence_ids"] = ["unrecorded"]
    elif bad in {"foreign_incident", "foreign_tenant"}:
        org = "a" if bad == "foreign_incident" else "b"
        if org == "a":
            now = datetime.now(UTC).isoformat()
            db.execute(
                "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    "other",
                    "a",
                    "other-alert",
                    "high",
                    "high",
                    "Other",
                    "[]",
                    "triage",
                    now,
                ),
            )
        task = bridge.records.create_incident_task(
            org, "other" if org == "a" else "inc-b", "endpoint", "endpoint", "foreign"
        )
        foreign = _evidence(bridge, org, task.task_id)
        result["evidence_ids"] = [foreign.evidence_id]
        result["findings"] = [
            {"claim": "Foreign", "evidence_ids": [foreign.evidence_id]}
        ]
    elif bad == "role":
        result["role"] = "network"
    elif bad == "uncited":
        result["findings"] = [{"claim": "Invented", "evidence_ids": ["unrecorded"]}]
    elif bad == "extra_assessment":
        result["severity"] = "critical"
    elif bad == "empty":
        result["evidence_ids"] = []
        result["findings"] = []
    else:
        result["status"] = "healthy"
    _complete(bridge, "a", first.task_id, result)
    done = _request(bridge)
    assert done.state == "failed"
    assert done.result is None
    assert done.findings == ()
    assert done.evidence_citations == ()
    assert done.to_output()["recorded_run"] is True


@pytest.mark.asyncio
async def test_cited_findings_persist_to_incident_run_and_downstream_report(db):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    alert = _alert().model_copy(update={"id": "alert-a"})
    report = await _base_report(alert)
    repo = SqliteIncidentRepository(db)
    notified = AsyncMock()
    deployment = SimpleNamespace(
        ticket_store=repo, notifier=SimpleNamespace(notify=notified)
    )
    workflow = _gated_workflow()
    workflow.nodes = [n for n in workflow.nodes if n.id != "ticket"]
    workflow.edges = [e for e in workflow.edges if e.target != "ticket"]
    waiting = await engine.execute_workflow(
        workflow, alert, report, "a", deployment=deployment, incident_id="inc-a"
    )
    task = bridge.records.list_tasks("a", incident_id="inc-a")[0]
    evidence = _evidence(bridge, "a", task.task_id)
    result = {
        "status": "completed",
        "role": "endpoint",
        "evidence_ids": [evidence.evidence_id],
        "findings": [
            {"claim": "Observed process", "evidence_ids": [evidence.evidence_id]}
        ],
    }
    _complete(bridge, "a", task.task_id, result)
    run_id = bridge.scheduler.get_job("a", task.task_id).run_id
    done = await engine.resume_run(waiting.run_id, "a", deployment=deployment)
    assert done is not None
    assert done.status == "COMPLETED"
    assert done.node_statuses["gate"] == "SUCCESS"
    assert done.node_outputs["gate"]["passed"] is True
    notified.assert_awaited_once()
    assert notified.await_args.args[0] == done.report
    assert done.report.verdict.severity == report.verdict.severity
    assert done.report.verdict.confidence == report.verdict.confidence
    assert done.report.verdict.recommended_actions == report.verdict.recommended_actions
    assert "Observed process" in done.report.verdict.summary
    assert evidence.evidence_id in done.report.evidence.context_notes
    citation = done.report.evidence_citations[0]
    assert citation["role"] == "endpoint"
    assert citation["run_id"] == run_id == done.node_outputs["ai"]["run_id"]
    assert citation["incident_id"] == "inc-a"
    assert citation["content_hash"] == evidence.content_hash
    persisted_run = engine.run_repo.get_run("a", waiting.run_id)
    persisted_incident = db.fetchone(
        "SELECT report_json FROM incidents WHERE org_id='a' AND ticket_id='inc-a'"
    )
    assert json.loads(persisted_run["base_report_json"]) == done.report.to_dict()
    assert json.loads(persisted_incident["report_json"]) == done.report.to_dict()
    again = await engine.resume_run(waiting.run_id, "a", deployment=deployment)
    assert again.report == done.report
    notified.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("serialized", [False, True])
async def test_canonical_assessment_preserves_severity_and_notes_its_origin(
    db, serialized
):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    notifier = AsyncMock()
    deployment = SimpleNamespace(
        ticket_store=SqliteIncidentRepository(db),
        notifier=SimpleNamespace(notify=notifier),
    )
    if serialized:
        await deployment.ticket_store.update_ticket_report(
            "inc-a", "a", await _base_report(_alert())
        )
    workflow = _gated_workflow()
    workflow.nodes = [n for n in workflow.nodes if n.id != "ticket"]
    workflow.edges = [e for e in workflow.edges if e.target != "ticket"]
    next(n for n in workflow.nodes if n.id == "gate").config = {
        "min_verdict_severity": "low"
    }
    waiting = await engine.execute_workflow(
        workflow, _alert(), org_id="a", incident_id="inc-a", deployment=deployment
    )
    task = bridge.records.list_tasks("a", incident_id="inc-a")[0]
    evidence = _evidence(bridge, "a", task.task_id)
    _complete(
        bridge,
        "a",
        task.task_id,
        {
            "status": "completed",
            "role": "endpoint",
            "evidence_ids": [evidence.evidence_id],
        },
    )
    done = await engine.resume_run(waiting.run_id, "a", deployment=deployment)
    assert done.status == "COMPLETED"
    notifier.assert_awaited_once()
    assert done.report.verdict.severity == Severity.HIGH
    assert done.report.verdict.confidence == (
        Confidence.MEDIUM if serialized else Confidence.HIGH
    )
    assert done.node_outputs["gate"]["verdict_check"] is True
    assert "canonical incident inc-a" in done.report.evidence.context_notes
    assert "does not establish" in done.report.verdict.summary


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "no_incident",
        "alert_mismatch",
        "tenant_mismatch",
        "severity",
        "confidence",
        "empty_summary",
        "invalid_report",
    ],
)
async def test_missing_valid_assessment_fails_before_any_specialist_or_side_effect(
    db, bad
):
    bridge = SpecialistBridge(db)
    engine = WorkflowEngine(db=db, specialist_bridge=bridge)
    incident = (
        None
        if bad == "no_incident"
        else "inc-b"
        if bad == "tenant_mismatch"
        else "inc-a"
    )
    alert = (
        _alert().model_copy(update={"id": "other-alert"})
        if bad == "alert_mismatch"
        else _alert()
    )
    if bad in {"severity", "confidence", "empty_summary", "invalid_report"}:
        column = (
            "summary"
            if bad == "empty_summary"
            else "report_json"
            if bad == "invalid_report"
            else bad
        )
        value = (
            ""
            if bad == "empty_summary"
            else '{"verdict":{"severity":"low"}}'
            if bad == "invalid_report"
            else "unassessed"
        )
        db.execute(
            f"UPDATE incidents SET {column}=? WHERE ticket_id='inc-a' AND org_id='a'",  # noqa: S608
            (value,),
        )
    notifier = AsyncMock()
    create_ticket = AsyncMock()
    deployment = SimpleNamespace(
        notifier=SimpleNamespace(notify=notifier),
        ticket_store=SimpleNamespace(create_ticket=create_ticket),
    )
    ctx = await engine.execute_workflow(
        _gated_workflow(),
        alert,
        org_id="a",
        incident_id=incident,
        deployment=deployment,
    )
    assert ctx.report is None
    assert ctx.status == "FAILED"
    assert ctx.outcome == "FAILED_BEFORE_SIDE_EFFECTS"
    assert ctx.node_statuses["ai"] == "NOT_EXECUTED"
    assert all(state == "DEAD" for state in ctx.edge_states.values())
    assert any("Report unavailable" in error for error in ctx.errors)
    assert (
        db.fetchone("SELECT COUNT(*) AS count FROM orchestration_tasks")["count"] == 0
    )
    notifier.assert_not_awaited()
    create_ticket.assert_not_awaited()
    saved = engine.run_repo.get_run("a", ctx.run_id)
    assert saved["status"] == "FAILED"
    assert json.loads(saved["base_report_json"]) == {}
    resumed = await engine.resume_run(ctx.run_id, "a", deployment=deployment)
    assert resumed.status == "FAILED"
    assert resumed.report is None
    notifier.assert_not_awaited()


def test_current_scheduler_failure_wins_over_old_completed_run(db):
    bridge = SpecialistBridge(db)
    first = _request(bridge)
    old = bridge.records.create_agent_run("a", first.task_id)
    bridge.records.transition_agent_run("a", old.run_id, "queued", "running")
    bridge.records.transition_agent_run(
        "a",
        old.run_id,
        "running",
        "completed",
        result={"status": "completed", "role": "endpoint"},
    )
    assert _request(bridge).state == "waiting"
    store = bridge.scheduler
    assert store.acquire_coordinator("owner", lease_seconds=300)
    lease = store.claim_next("owner", "worker", ["endpoint"], lease_seconds=300)
    assert lease is not None
    store.fail(lease, "current attempt failed", retryable=False)
    done = _request(bridge)
    assert done.state == "failed"
    assert done.run_id == lease.run_id != old.run_id


@pytest.mark.parametrize(
    "mismatch", ["job_role", "job_incident", "run_task", "run_incident"]
)
def test_scheduler_and_run_scope_must_match_admitted_task(db, mismatch):
    bridge = SpecialistBridge(db)
    first = _request(bridge)
    evidence = _evidence(bridge, "a", first.task_id)
    _complete(
        bridge,
        "a",
        first.task_id,
        {
            "status": "completed",
            "role": "endpoint",
            "evidence_ids": [evidence.evidence_id],
        },
    )
    job = bridge.scheduler.get_job("a", first.task_id)
    if mismatch.startswith("job"):
        table, column, record_id = (
            "orchestration_scheduler_jobs",
            "task_id",
            first.task_id,
        )
        payload = job.model_dump(mode="json")
        payload["role" if mismatch == "job_role" else "incident_id"] = (
            "network" if mismatch == "job_role" else "inc-b"
        )
    else:
        table, column, record_id = "orchestration_agent_runs", "run_id", job.run_id
        payload = bridge.records.get_agent_run("a", job.run_id).model_dump(mode="json")
        payload["task_id" if mismatch == "run_task" else "incident_id"] = (
            "foreign-task" if mismatch == "run_task" else "inc-b"
        )
    db.execute(
        f"UPDATE {table} SET payload_json=? WHERE org_id=? AND {column}=?",  # noqa: S608
        (json.dumps(payload), "a", record_id),
    )
    assert _request(bridge).state == "failed"
