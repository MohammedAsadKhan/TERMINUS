"""Citation preservation regressions; all persistence uses a private temporary DB."""

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from terminus.agent.investigator import InvestigationAgent
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
from terminus.pipeline.runner import PipelineRunner
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database
from terminus.storage.repositories import SqliteIncidentRepository
from terminus.ticketing.memory import MemoryTickets


@pytest.fixture(autouse=True)
def forbid_default_database(monkeypatch):
    """Fail if a test accidentally reaches the user's default database."""

    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must inject their temporary database")

    monkeypatch.setattr(Database, "get_instance", forbidden)


@pytest.fixture
def db(tmp_path: Path):
    database = Database(str(tmp_path / "citations.db"))
    yield database
    database._get_connection().close()


@pytest.fixture
def report():
    alert = SiemAlert(
        id="citation-alert", rule_id=1001, level=12, agent_name="test-host"
    )
    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(
            alert_id=alert.id, tier=Tier.TRIAGE, should_investigate=True, reason="test"
        ),
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="test assessment",
        ),
        evidence=Evidence(
            alert=alert,
            agent_name=alert.agent_name,
            threat_intel="test",
            context_notes="test",
        ),
        evidence_citations=[
            {
                "source": "ThreatIntel",
                "indicator": "test-indicator",
                "malicious": False,
                "timestamp": "2026-10-03T00:00:00+00:00",
                "details": {"hits": 0},
            },
            {
                "source": "Tool:PayloadDeobfuscator",
                "suspicious_commands": ["test-command"],
            },
        ],
    )


def test_report_json_round_trip_and_legacy_default(report):
    restored = InvestigationReport.from_dict(json.loads(json.dumps(report.to_dict())))
    assert restored == report
    legacy = report.to_dict()
    del legacy["evidence_citations"]
    first = InvestigationReport.from_dict(legacy)
    second = InvestigationReport.from_dict(legacy)
    assert first.evidence_citations == []
    first.evidence_citations.append({"source": "first-only"})
    assert second.evidence_citations == []


@pytest.mark.asyncio
async def test_investigator_retains_react_citations(report):
    agent = InvestigationAgent(llm=SimpleNamespace(respond_json=AsyncMock()))
    agent.policy_engine = SimpleNamespace(evaluate=lambda *_: report.policy)
    agent.react_agent = SimpleNamespace(
        run_investigation=AsyncMock(
            return_value=(report.verdict, report.evidence_citations, report.evidence)
        )
    )
    result = await agent.investigate(report.evidence.alert, OrgId("citation-org"))
    assert result.evidence_citations == report.evidence_citations


@pytest.mark.asyncio
async def test_sqlite_citations_default_override_and_reopen(db, report):
    store = SqliteIncidentRepository(db=db)
    ticket = await store.create_ticket(report, "citation-org")
    assert (await store.get_ticket(ticket, "citation-org"))[
        "evidence_citations"
    ] == report.evidence_citations
    assert (await store.list_tickets("citation-org"))[0][
        "evidence_citations"
    ] == report.evidence_citations
    empty_report = replace(
        report,
        alert_id="empty-alert",
        evidence=replace(
            report.evidence,
            alert=report.evidence.alert.model_copy(update={"id": "empty-alert"}),
        ),
    )
    empty_ticket = await store.create_ticket(
        empty_report, "citation-org", evidence_citations=[]
    )
    assert (await store.get_ticket(empty_ticket, "citation-org"))[
        "evidence_citations"
    ] == []
    override = [{"source": "explicit-override"}]
    override_report = replace(
        report,
        alert_id="override-alert",
        evidence=replace(
            report.evidence,
            alert=report.evidence.alert.model_copy(update={"id": "override-alert"}),
        ),
    )
    overridden = await store.create_ticket(
        override_report, "citation-org", evidence_citations=override
    )
    assert (await store.get_ticket(overridden, "citation-org"))[
        "evidence_citations"
    ] == override
    reopened_db = Database(db.db_path)
    try:
        reopened = SqliteIncidentRepository(db=reopened_db)
        assert (await reopened.get_ticket(ticket, "citation-org"))[
            "evidence_citations"
        ] == report.evidence_citations
    finally:
        reopened_db._get_connection().close()


@pytest.mark.asyncio
async def test_memory_tickets_expose_citations(report):
    store = MemoryTickets()
    org = OrgId("citation-org")
    ticket = await store.create_ticket(report, org)
    assert (await store.get_ticket(ticket, org))[
        "evidence_citations"
    ] == report.evidence_citations
    assert (await store.list_tickets(org))[0][
        "evidence_citations"
    ] == report.evidence_citations


@pytest.mark.asyncio
async def test_pipeline_claim_replay_retains_citations(db, report, monkeypatch):
    from terminus.pipeline import runner as runner_module

    monkeypatch.setattr(
        runner_module,
        "GraphEventStore",
        lambda **kwargs: SimpleNamespace(record=lambda *_: None),
    )
    deployment = SimpleNamespace(
        agent=SimpleNamespace(investigate=AsyncMock(return_value=report)),
        notifier=SimpleNamespace(notify=AsyncMock()),
        ticket_store=SqliteIncidentRepository(db=db),
    )
    runner = PipelineRunner(deployment=deployment, db=db)
    first = await runner.process_alert(report.evidence.alert, "citation-org")
    replayed = await runner.process_alert(report.evidence.alert, "citation-org")
    assert (
        first.evidence_citations
        == replayed.evidence_citations
        == report.evidence_citations
    )
    assert deployment.agent.investigate.await_count == 1
    tickets = await deployment.ticket_store.list_tickets("citation-org")
    assert len(tickets) == 1
    assert tickets[0]["evidence_citations"] == report.evidence_citations


@pytest.mark.asyncio
async def test_workflow_reinvestigation_retains_new_citations(db, report, monkeypatch):
    from terminus.pipeline import workflow_engine as engine_module

    revised = replace(
        report,
        evidence_citations=[
            {"source": "second-investigation", "details": {"verified": True}}
        ],
    )
    monkeypatch.setattr(
        engine_module,
        "InvestigationAgent",
        lambda **kwargs: SimpleNamespace(investigate=AsyncMock(return_value=revised)),
    )
    base = replace(report, campaign_id="campaign-test", campaign_alert_count=2)
    deployment = SimpleNamespace(
        agent=SimpleNamespace(llm=None),
        ticket_store=SqliteIncidentRepository(db=db),
        notifier=SimpleNamespace(notify=AsyncMock()),
    )
    workflow = Workflow(
        id="citation-workflow",
        name="Citation test",
        nodes=[
            WorkflowNode(id="trigger", type="trigger_wazuh"),
            WorkflowNode(id="investigate", type="agent_llm"),
            WorkflowNode(id="ticket", type="tool_jira"),
        ],
        edges=[
            WorkflowEdge(id="first", source="trigger", target="investigate"),
            WorkflowEdge(id="second", source="investigate", target="ticket"),
        ],
    )
    ctx = await WorkflowEngine(db=db).execute_workflow(
        workflow=workflow,
        alert=report.evidence.alert,
        base_report=base,
        org_id="citation-org",
        deployment=deployment,
    )
    assert ctx.status == "COMPLETED", ctx.errors
    assert ctx.report.evidence_citations == revised.evidence_citations
    assert ctx.report.campaign_id == base.campaign_id
    tickets = await deployment.ticket_store.list_tickets("citation-org")
    assert len(tickets) == 1
    assert tickets[0]["evidence_citations"] == revised.evidence_citations


@pytest.mark.asyncio
async def test_incident_api_returns_citation_objects(db, report, monkeypatch):
    # server.deps seeds repository data at import; keep those writes isolated too.
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: db)
    from terminus.server.console_api import router
    from terminus.server.deps import (
        get_current_org,
        get_pipeline_runner,
        get_webhook_org,
    )
    from terminus.server.routers import webhook_router

    store = SqliteIncidentRepository(db=db)
    ticket = await store.create_ticket(report, "citation-org")
    runner = SimpleNamespace(deployment=SimpleNamespace(ticket_store=store))
    app = FastAPI()
    app.include_router(router)
    app.include_router(webhook_router)
    app.dependency_overrides[get_pipeline_runner] = lambda: runner
    app.dependency_overrides[get_webhook_org] = lambda: OrgId("citation-org")
    app.dependency_overrides[get_current_org] = lambda: OrgId("citation-org")
    with TestClient(app) as client:
        response = client.get(f"/incidents/{ticket}")
        assert response.status_code == 200, response.text
        assert response.json()["evidence_citations"] == report.evidence_citations
        listed = client.get("/incidents")
        assert listed.status_code == 200, listed.text
        assert listed.json()[0]["evidence_citations"] == report.evidence_citations
