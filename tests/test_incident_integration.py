"""Server-wired incident persistence, workflow linkage, and replay regressions."""

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from terminus.config import Settings
from terminus.core.base import ConflictError
from terminus.core.ids import OrgId
from terminus.models import (
    Confidence,
    Evidence,
    InvestigationReport,
    PolicyResult,
    Severity,
    SiemAlert,
    Tier,
    Verdict,
    Workflow,
    WorkflowEdge,
    WorkflowNode,
)
from terminus.storage.db import Database
from terminus.storage.repositories import SqliteIncidentRepository


@pytest.fixture
def server_pipeline(tmp_path, monkeypatch):
    # deps seeds repositories on first import: redirect every singleton lookup first.
    db = Database(str(tmp_path / "incident-integration.db"))
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: db)
    from terminus.server import deps

    settings = Settings(
        _env_file=None,
        llm_api_key="",
        wazuh_url="",
        slack_webhook="",
        twilio_sid="",
        twilio_token="",
        jira_url="",
        jira_token="",
    )
    runner = deps.get_pipeline_runner(settings)
    alert = SiemAlert(
        id="integration-alert",
        rule_id="5710",
        level=12,
        description="Credential theft detected",
        src_ip="198.51.100.77",
        agent_name="test-workstation",
        full_log="Observed credential request",
    )
    report = InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(
            alert_id=alert.id,
            tier=Tier.ESCALATE,
            should_investigate=True,
            reason="High severity credential theft",
        ),
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Credential theft requires investigation",
            recommended_actions=["Review endpoint telemetry"],
        ),
        evidence=Evidence(
            alert=alert,
            agent_name=alert.agent_name,
            threat_intel="Test evidence",
            context_notes="Observed request",
        ),
        evidence_citations=[
            {"source": "siem", "details": {"alert_id": alert.id, "verified": True}},
        ],
    )
    monkeypatch.setattr(runner.deployment.agent, "investigate", AsyncMock(return_value=report))
    monkeypatch.setattr(runner.deployment.notifier, "notify", AsyncMock())
    return SimpleNamespace(db=db, deps=deps, settings=settings, runner=runner, alert=alert, report=report)


def test_default_server_ingest_survives_restart_and_replay(server_pipeline, monkeypatch):
    env = server_pipeline
    from terminus.server.app import create_app

    assert isinstance(env.runner.deployment.ticket_store, SqliteIncidentRepository)
    app = create_app()
    app.dependency_overrides[env.deps.get_pipeline_runner] = lambda: env.runner
    app.dependency_overrides[env.deps.get_webhook_org] = lambda: OrgId("integration-org")
    app.dependency_overrides[env.deps.get_current_org] = lambda: OrgId("integration-org")
    app.dependency_overrides[env.deps.require_operator] = lambda: None
    # Direct client requests exercise real routes and exception handlers without
    # starting unrelated scheduler and sweeper lifespan tasks.
    client = TestClient(app)
    response = client.post("/webhook/alert", json=env.alert.model_dump())
    assert response.status_code == 200, response.text
    assert response.json()["evidence_citations"] == env.report.evidence_citations
    listing = client.get("/incidents")
    assert listing.status_code == 200, listing.text
    assert len(listing.json()) == 1
    ticket = listing.json()[0]
    ticket_id = ticket["ticket_id"]
    assert ticket["evidence_citations"] == env.report.evidence_citations
    detail = client.get(f"/incidents/{ticket_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence_citations"] == env.report.evidence_citations
    env.runner.deployment.agent.investigate.assert_awaited_once()

    reopened = Database(env.db.db_path)
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: reopened)
    restarted = env.deps.get_pipeline_runner(env.settings)
    investigate = AsyncMock(side_effect=AssertionError("Replay must not investigate"))
    monkeypatch.setattr(restarted.deployment.agent, "investigate", investigate)
    app.dependency_overrides[env.deps.get_pipeline_runner] = lambda: restarted
    retained = client.get(f"/incidents/{ticket_id}")
    assert retained.status_code == 200, retained.text
    assert retained.json()["evidence_citations"] == env.report.evidence_citations
    replay = client.post("/webhook/alert", json=env.alert.model_dump())
    assert replay.status_code == 200, replay.text
    assert replay.json() == response.json()
    assert [item["ticket_id"] for item in client.get("/incidents").json()] == [ticket_id]
    investigate.assert_not_awaited()
    claim = restarted.claim_repo.get_claim("integration-org", env.alert.id)
    graph = reopened.fetchone(
        "SELECT incident_id FROM graph_events WHERE org_id = ? AND alert_id = ?",
        ("integration-org", env.alert.id),
    )
    assert claim["incident_id"] == graph["incident_id"] == ticket_id

    closed = client.post(
        f"/incidents/{ticket_id}/action",
        json={"action_type": "close_ticket", "resolution_category": "true_positive", "resolution_notes": " Verified theft "},
    )
    assert closed.status_code == 200, closed.text
    closed_db = Database(env.db.db_path)
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: closed_db)
    app.dependency_overrides[env.deps.get_pipeline_runner] = lambda: env.deps.get_pipeline_runner(env.settings)
    durable_closed = client.get(f"/incidents/{ticket_id}").json()
    assert durable_closed["status"] == "RESOLVED"
    assert durable_closed["resolution_category"] == "true_positive"
    assert durable_closed["resolution_notes"] == "Verified theft"
    assert durable_closed["resolved_at"]
    reopened_response = client.post(f"/incidents/{ticket_id}/action", json={"action_type": "reopen_ticket"})
    assert reopened_response.status_code == 200, reopened_response.text
    open_db = Database(env.db.db_path)
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: open_db)
    durable_open = client.get(f"/incidents/{ticket_id}").json()
    assert durable_open["status"] == "OPEN"
    assert not durable_open["resolved_at"]
    assert durable_open["evidence_citations"] == env.report.evidence_citations

    app.dependency_overrides[env.deps.get_current_org] = lambda: OrgId("other-org")
    app.dependency_overrides[env.deps.get_webhook_org] = lambda: OrgId("other-org")
    assert client.get(f"/incidents/{ticket_id}").status_code == 404
    assert client.get("/incidents").json() == []
    client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("include_ticket_node", [False, True])
async def test_workflow_uses_canonical_incident_and_persists_final_citations(
    server_pipeline, monkeypatch, include_ticket_node,
):
    env = server_pipeline
    from terminus.pipeline import workflow_engine

    revised = replace(
        env.report,
        verdict=env.report.verdict.model_copy(update={"summary": "Workflow verified credential theft"}),
        evidence_citations=[{"source": "workflow-investigator", "details": {"verified": True}}],
    )
    monkeypatch.setattr(
        workflow_engine,
        "InvestigationAgent",
        lambda **kwargs: SimpleNamespace(investigate=AsyncMock(return_value=revised)),
    )
    workflow = Workflow(
        id="integration-workflow",
        name="Credential response",
        enabled=True,
        nodes=[
            WorkflowNode(id="trigger", type="trigger_wazuh"),
            WorkflowNode(id="investigate", type="agent_llm"),
        ],
        edges=[
            WorkflowEdge(id="first", source="trigger", target="investigate"),
        ],
    )
    if include_ticket_node:
        workflow.nodes.append(WorkflowNode(id="ticket", type="tool_jira"))
        workflow.edges.append(WorkflowEdge(id="second", source="investigate", target="ticket"))
    env.runner.workflow_repo.save(workflow, "integration-org")
    original_execute = env.runner.workflow_engine.execute_workflow
    contexts = []

    async def execute_with_persisted_incident(**kwargs):
        tickets = await env.runner.deployment.ticket_store.list_tickets("integration-org")
        assert len(tickets) == 1, "Canonical incident must exist before workflow execution"
        ctx = await original_execute(**kwargs)
        contexts.append(ctx)
        return ctx

    monkeypatch.setattr(env.runner.workflow_engine, "execute_workflow", execute_with_persisted_incident)
    result = await env.runner.process_alert(env.alert, "integration-org")
    tickets = await env.runner.deployment.ticket_store.list_tickets("integration-org")
    assert len(tickets) == 1
    ticket = tickets[0]
    assert ticket["summary"] == revised.verdict.summary
    assert ticket["evidence_citations"] == result.evidence_citations == revised.evidence_citations
    assert contexts[0].status == "COMPLETED", contexts[0].errors
    assert contexts[0].incident_id == ticket["ticket_id"]
    run = env.runner.workflow_engine.run_repo.get_run("integration-org", contexts[0].run_id)
    claim = env.runner.claim_repo.get_claim("integration-org", env.alert.id)
    graph = env.db.fetchone(
        "SELECT incident_id FROM graph_events WHERE org_id = ? AND alert_id = ?",
        ("integration-org", env.alert.id),
    )
    assert run["incident_id"] == claim["incident_id"] == graph["incident_id"] == ticket["ticket_id"]
    from terminus.orchestration.storage import OrchestrationStore

    store = OrchestrationStore(env.db)
    task = store.create_incident_task(
        "integration-org", ticket["ticket_id"], "forensics", "analyst", "Verify credential theft",
    )
    evidence = store.create_evidence(
        "integration-org", task.task_id, "siem", datetime.now(UTC),
        content={"alert_id": env.alert.id},
    )
    reopened_store = OrchestrationStore(Database(env.db.db_path))
    assert reopened_store.list_tasks("integration-org", incident_id=ticket["ticket_id"]) == [task]
    assert reopened_store.list_evidence("integration-org", incident_id=ticket["ticket_id"]) == [evidence]
    assert reopened_store.list_tasks("other-org", incident_id=ticket["ticket_id"]) == []
    assert reopened_store.list_evidence("other-org", incident_id=ticket["ticket_id"]) == []
    assert await env.runner.process_alert(env.alert, "integration-org") == result
    env.runner.deployment.agent.investigate.assert_awaited_once()


@pytest.mark.asyncio
async def test_active_duplicate_claim_does_not_execute_again(server_pipeline):
    env = server_pipeline
    claimed, _ = env.runner.claim_repo.claim_alert("integration-org", env.alert.id)
    assert claimed
    with pytest.raises(ConflictError):
        await env.runner.process_alert(env.alert, "integration-org")
    env.runner.deployment.agent.investigate.assert_not_awaited()
    env.runner.deployment.notifier.notify.assert_not_awaited()
    assert await env.runner.deployment.ticket_store.list_tickets("integration-org") == []


@pytest.mark.asyncio
async def test_investigation_failure_can_retry_without_losing_single_incident(server_pipeline):
    env = server_pipeline
    investigate = env.runner.deployment.agent.investigate
    investigate.side_effect = [RuntimeError("Investigation unavailable"), env.report]
    with pytest.raises(RuntimeError, match="Investigation unavailable"):
        await env.runner.process_alert(env.alert, "integration-org")
    claim = env.runner.claim_repo.get_claim("integration-org", env.alert.id)
    assert claim["outcome"] == "FAILED_BEFORE_SIDE_EFFECTS"
    assert claim["side_effects"] == 0
    result = await env.runner.process_alert(env.alert, "integration-org")
    assert result.incident_id
    assert len(await env.runner.deployment.ticket_store.list_tickets("integration-org")) == 1
    env.runner.deployment.notifier.notify.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown_outcome", [False, True])
async def test_configured_jira_keeps_local_incident_id_and_never_reissues_export(
    server_pipeline, monkeypatch, unknown_outcome,
):
    env = server_pipeline
    external = SimpleNamespace(
        create_ticket=AsyncMock(
            side_effect=TimeoutError("Connection lost after dispatch") if unknown_outcome else None,
            return_value="SEC-123",
        ),
    )
    monkeypatch.setattr(env.deps, "JiraTickets", lambda **kwargs: external)
    settings = env.settings.model_copy(update={"jira_url": "https://jira.example.invalid", "jira_token": "test"})
    runner = env.deps.get_pipeline_runner(settings)
    monkeypatch.setattr(runner.deployment.agent, "investigate", AsyncMock(return_value=env.report))
    monkeypatch.setattr(runner.deployment.notifier, "notify", AsyncMock())
    assert isinstance(runner.deployment.ticket_store, SqliteIncidentRepository)
    result = await runner.process_alert(env.alert, "integration-org")
    tickets = await runner.deployment.ticket_store.list_tickets("integration-org")
    assert len(tickets) == 1
    local_id = tickets[0]["ticket_id"]
    assert local_id != "SEC-123"
    assert result.incident_id == local_id
    mapping = await runner.deployment.ticket_store.get_external_ticket(local_id, "integration-org")
    assert mapping["state"] == ("unknown" if unknown_outcome else "bound")
    assert mapping["external_id"] == (None if unknown_outcome else "SEC-123")
    external.create_ticket.assert_awaited_once()

    restarted_db = Database(env.db.db_path)
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: restarted_db)
    restarted = env.deps.get_pipeline_runner(settings)
    investigate = AsyncMock(side_effect=AssertionError("Replay must not investigate"))
    monkeypatch.setattr(restarted.deployment.agent, "investigate", investigate)
    replay = await restarted.process_alert(env.alert, "integration-org")
    assert replay.incident_id == local_id
    assert await restarted.deployment.export_ticket(local_id, replay, OrgId("integration-org")) is None
    external.create_ticket.assert_awaited_once()
    investigate.assert_not_awaited()
    retained = await restarted.deployment.ticket_store.get_external_ticket(local_id, "integration-org")
    assert retained == mapping
