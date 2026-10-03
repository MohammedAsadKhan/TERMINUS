"""Phase 5 Test Suite: Pipeline Runner, Idempotency & Sweeper.

Covers T-RUN-1 through T-RUN-10:
- T-RUN-1: Alert claim idempotency (D5)
- T-RUN-2: Atomic re-claim after safe failure (D5)
- T-RUN-3: Priority-ordered first-match workflow execution (D2)
- T-RUN-4: Base autonomous investigation runs before workflow (D3)
- T-RUN-5: Ticketing gap filling when workflow creates no ticket (D4)
- T-RUN-6: Ticketing gap filling suppressed when workflow created ticket (D4)
- T-RUN-7: Notification gap filling when workflow did not notify (D4)
- T-RUN-8: Sweeper transitions stale RUNNING runs to INTERRUPTED (D24)
- T-RUN-9: Sweeper resolves expired pending approvals and resumes run (D14, D24)
- T-RUN-10: Sweeper surfaces interrupted runs with side effects (D24)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

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
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.runner import PipelineRunner
from terminus.pipeline.sweeper import run_sweeper_cycle
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAlertClaimRepository,
    SqliteApprovalRepository,
    SqliteWorkflowRepository,
    SqliteWorkflowRunRepository,
)


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_phase5.db"
    db = Database(str(db_file))
    Database._instance = db
    return db


def create_sample_alert(alert_id: str = "alt-001", level: int = 12, rule_id: str = "5710") -> SiemAlert:
    return SiemAlert(
        id=alert_id,
        rule_id=rule_id,
        level=level,
        description="SSH brute force attempt",
        src_ip="198.51.100.22",
        full_log="Failed password for root from 198.51.100.22",
    )


def create_sample_report(alert: SiemAlert, tier: Tier = Tier.ESCALATE, should_investigate: bool = True) -> InvestigationReport:
    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(
            alert_id=alert.id,
            tier=tier,
            should_investigate=should_investigate,
            reason="High severity alert",
        ),
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Brute force attack detected",
            recommended_actions=["Block IP", "Notify SOC"],
        ),
        evidence=Evidence(
            alert=alert,
            agent_name="agent-01",
            threat_intel="Known malicious IP",
            context_notes="Multiple failures",
        ),
    )


def create_mock_deployment(base_report: InvestigationReport) -> PipelineDeployment:
    policy_engine = MagicMock()
    policy_engine.evaluate = MagicMock(return_value=base_report.policy)

    agent = MagicMock()
    agent.investigate = AsyncMock(return_value=base_report)

    notifier = MagicMock()
    notifier.notify = AsyncMock(return_value=True)

    ticket_store = MagicMock()
    ticket_store.create_ticket = AsyncMock(return_value="TICK-MOCK-999")

    return PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )


@pytest.mark.anyio
async def test_t_run_1_alert_claim_idempotency(temp_db):
    """T-RUN-1: Duplicate alert processing returns stored report and avoids duplicate LLM / notifications."""
    alert = create_sample_alert("alt-idem-1")
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)

    runner = PipelineRunner(deployment=deployment, db=temp_db)

    # First run
    res1 = await runner.process_alert(alert, "org-test-idem")
    assert res1.alert_id == alert.id
    assert deployment.agent.investigate.call_count == 1
    assert deployment.notifier.notify.call_count == 1

    # Second run with same alert ID
    res2 = await runner.process_alert(alert, "org-test-idem")
    assert res2.alert_id == alert.id
    # Should NOT have invoked LLM agent or notifier a second time
    assert deployment.agent.investigate.call_count == 1
    assert deployment.notifier.notify.call_count == 1


@pytest.mark.anyio
async def test_t_run_2_atomic_reclaim_after_safe_failure(temp_db):
    """T-RUN-2: Alert whose prior run failed before side effects can be atomically re-claimed."""
    claim_repo = SqliteAlertClaimRepository(temp_db)
    org_id = "org-reclaim"
    alert_id = "alt-rec-1"

    # Seed an alert claim that failed before side effects
    claim_repo.claim_alert(org_id, alert_id)
    claim_repo.update_claim_status(
        org_id=org_id,
        alert_id=alert_id,
        status="FAILED",
        outcome="FAILED_BEFORE_SIDE_EFFECTS",
        side_effects=0,
        report=None,
    )

    alert = create_sample_alert(alert_id)
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)
    runner = PipelineRunner(deployment=deployment, db=temp_db)

    # Processing should succeed via re-claim and increment attempt
    res = await runner.process_alert(alert, org_id)
    assert res.alert_id == alert_id

    claim = claim_repo.get_claim(org_id, alert_id)
    assert claim is not None
    assert claim["attempt"] == 2
    assert claim["status"] == "COMPLETED"
    assert claim["outcome"] == "HANDLED"


@pytest.mark.anyio
async def test_t_run_3_first_match_workflow_wins(temp_db):
    """T-RUN-3: First matching workflow (ordered by priority ASC, created_at ASC) wins."""
    wf_repo = SqliteWorkflowRepository(temp_db)
    org_id = "org-prio"

    # Workflow 1 (priority 10)
    wf1 = Workflow(
        id="wf-prio-10",
        name="High Priority Workflow",
        enabled=True,
        priority=10,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#soc-high"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    # Workflow 2 (priority 20)
    wf2 = Workflow(
        id="wf-prio-20",
        name="Lower Priority Workflow",
        enabled=True,
        priority=20,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#soc-low"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow(org_id, wf1)
    wf_repo.save_workflow(org_id, wf2)

    alert = create_sample_alert("alt-prio-1", level=10)
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)
    runner = PipelineRunner(deployment=deployment, db=temp_db)

    await runner.process_alert(alert, org_id)

    run_repo = SqliteWorkflowRunRepository(temp_db)
    runs = run_repo.list_for_org(org_id)
    assert len(runs) == 1
    assert runs[0]["workflow_id"] == "wf-prio-10"


@pytest.mark.anyio
async def test_t_run_4_base_investigation_runs_first(temp_db):
    """T-RUN-4: Base investigation runs first and its report is supplied to workflow engine."""
    alert = create_sample_alert("alt-base-1")
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)

    wf_repo = SqliteWorkflowRepository(temp_db)
    org_id = "org-base-wf"

    wf = Workflow(
        id="wf-base-check",
        name="Base Check",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    final_report = await runner.process_alert(alert, org_id)

    assert deployment.agent.investigate.call_count == 1
    assert final_report.alert_id == alert.id
    assert final_report.verdict.summary == "Brute force attack detected"


@pytest.mark.anyio
async def test_t_run_5_ticketing_gap_filling_when_no_ticket(temp_db):
    """T-RUN-5: Runner fills gap by creating ticket if workflow did not create one."""
    alert = create_sample_alert("alt-gap-tick-1")
    report = create_sample_report(alert, should_investigate=True)
    deployment = create_mock_deployment(report)

    # Workflow without tool_jira
    wf_repo = SqliteWorkflowRepository(temp_db)
    org_id = "org-gap-tick"

    wf = Workflow(
        id="wf-no-ticket",
        name="No Ticket Workflow",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    await runner.process_alert(alert, org_id)

    assert deployment.ticket_store.create_ticket.call_count == 1


@pytest.mark.anyio
async def test_t_run_6_ticketing_gap_filling_suppressed_when_workflow_created_ticket(temp_db):
    """T-RUN-6: Gap-filling ticket creation is skipped if workflow already executed tool_jira."""
    alert = create_sample_alert("alt-gap-suppr-1")
    report = create_sample_report(alert, should_investigate=True)
    deployment = create_mock_deployment(report)

    wf_repo = SqliteWorkflowRepository(temp_db)
    org_id = "org-suppr-tick"

    wf = Workflow(
        id="wf-has-jira",
        name="Jira Workflow",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="tool_jira", config={"project_key": "SEC"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    await runner.process_alert(alert, org_id)

    # Only the workflow's tool_jira should have called ticket_store.create_ticket (1 time total)
    assert deployment.ticket_store.create_ticket.call_count == 1


@pytest.mark.anyio
async def test_t_run_7_notification_gap_filling(temp_db):
    """T-RUN-7: Gap-filling notification is sent if workflow did not notify slack."""
    alert = create_sample_alert("alt-notif-1")
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)

    wf_repo = SqliteWorkflowRepository(temp_db)
    org_id = "org-notif-gap"

    # Workflow without tool_slack
    wf = Workflow(
        id="wf-no-slack",
        name="No Slack Workflow",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="tool_jira", config={"project_key": "SEC"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    await runner.process_alert(alert, org_id)

    # Default notifier should be called by gap filler
    assert deployment.notifier.notify.call_count == 1


@pytest.mark.anyio
async def test_t_run_8_sweeper_stale_running_runs(temp_db):
    """T-RUN-8: Sweeper transitions stale RUNNING runs to INTERRUPTED."""
    run_repo = SqliteWorkflowRunRepository(temp_db)
    approval_repo = SqliteApprovalRepository(temp_db)
    claim_repo = SqliteAlertClaimRepository(temp_db)
    workflow_engine = WorkflowEngine(db=temp_db)

    org_id = "org-sweep-stale"
    run_id = "run-stale-001"
    alert_id = "alt-stale-001"

    # Create stale run with heartbeat 10 minutes in past
    stale_time = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    run_repo.create_run(
        org_id=org_id,
        run_id=run_id,
        workflow_id="wf-1",
        alert_id=alert_id,
        definition_snapshot={},
        alert={"id": alert_id},
        base_report={},
    )
    # Manually update heartbeat_at to stale time
    temp_db.execute(
        "UPDATE workflow_runs SET heartbeat_at = ? WHERE run_id = ?",
        (stale_time, run_id),
    )

    # Run sweeper
    res = await run_sweeper_cycle(
        run_repo=run_repo,
        approval_repo=approval_repo,
        workflow_engine=workflow_engine,
        claim_repo=claim_repo,
        max_heartbeat_age_seconds=300,
    )

    assert res["interrupted_runs"] == 1
    updated_run = run_repo.get_run(org_id, run_id)
    assert updated_run["status"] == "INTERRUPTED"
    assert updated_run["outcome"] == "INTERRUPTED"


@pytest.mark.anyio
async def test_t_run_9_sweeper_expires_pending_approvals_and_resumes(temp_db):
    """T-RUN-9: Sweeper resolves expired pending approvals and resumes run on false port."""
    run_repo = SqliteWorkflowRunRepository(temp_db)
    approval_repo = SqliteApprovalRepository(temp_db)
    wf_repo = SqliteWorkflowRepository(temp_db)
    workflow_engine = WorkflowEngine(db=temp_db)

    org_id = "org-sweep-apprv"
    alert = create_sample_alert("alt-apprv-1")
    report = create_sample_report(alert)
    deployment = create_mock_deployment(report)

    wf = Workflow(
        id="wf-apprv-sweep",
        name="Approval Workflow",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="condition_approval", config={"timeout_minutes": 5}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#approved"}),
            WorkflowNode(id="n4", type="tool_slack", config={"channel": "#rejected-or-expired"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
            WorkflowEdge(id="e3", source="n2", target="n4", source_handle="false"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    # Execute workflow -> should pause at condition_approval
    ctx = await workflow_engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id=org_id,
        deployment=deployment,
    )
    assert ctx.status == "WAITING_APPROVAL"

    # Make the approval expired in DB
    past_iso = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    temp_db.execute("UPDATE workflow_approvals SET expires_at = ? WHERE run_id = ?", (past_iso, ctx.run_id))

    # Run sweeper
    res = await run_sweeper_cycle(
        run_repo=run_repo,
        approval_repo=approval_repo,
        workflow_engine=workflow_engine,
        deployment=deployment,
    )

    assert res["expired_approvals"] == 1

    # Check run status after resumption
    resumed_run = run_repo.get_run(org_id, ctx.run_id)
    assert resumed_run["status"] == "COMPLETED"
    assert resumed_run["outcome"] == "HANDLED"

    # Check that false handle branch executed (node n4) and not true handle branch (node n3)
    node_runs = run_repo.get_node_runs(org_id, ctx.run_id)
    executed_node_ids = [nr["node_id"] for nr in node_runs]
    assert "n4" in executed_node_ids
    assert "n3" not in executed_node_ids


@pytest.mark.anyio
async def test_t_run_10_sweeper_surfaces_interrupted_run_with_side_effects(temp_db):
    """T-RUN-10: Sweeper marks run as INTERRUPTED and preserves side_effects=1."""
    run_repo = SqliteWorkflowRunRepository(temp_db)
    approval_repo = SqliteApprovalRepository(temp_db)
    claim_repo = SqliteAlertClaimRepository(temp_db)
    workflow_engine = WorkflowEngine(db=temp_db)

    org_id = "org-sweep-side-effects"
    run_id = "run-side-eff-001"
    alert_id = "alt-side-eff-001"

    stale_time = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
    run_repo.create_run(
        org_id=org_id,
        run_id=run_id,
        workflow_id="wf-1",
        alert_id=alert_id,
        definition_snapshot={},
        alert={"id": alert_id},
        base_report={},
    )
    # Set side_effects = 1 and stale heartbeat
    temp_db.execute(
        "UPDATE workflow_runs SET heartbeat_at = ?, side_effects = 1 WHERE run_id = ?",
        (stale_time, run_id),
    )

    res = await run_sweeper_cycle(
        run_repo=run_repo,
        approval_repo=approval_repo,
        workflow_engine=workflow_engine,
        claim_repo=claim_repo,
        max_heartbeat_age_seconds=300,
    )

    assert res["interrupted_runs"] == 1
    updated_run = run_repo.get_run(org_id, run_id)
    assert updated_run["status"] == "INTERRUPTED"
    assert updated_run["outcome"] == "INTERRUPTED"
    assert updated_run["side_effects_executed"] == 1
