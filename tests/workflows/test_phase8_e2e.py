"""Phase 8 Test Suite: Full End-to-End Integration Suite.

Covers T-E2E-1 through T-E2E-3:
- T-E2E-1: Complete Happy Path investigation, workflow matching, and gap-filling
- T-E2E-2: Human approval gate pause, resolution, and resumption lifecycle
- T-E2E-3: Containment safety guardrail block and error path routing
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

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
    db_file = tmp_path / "test_phase8_e2e.db"
    db = Database(str(db_file))
    Database._instance = db
    return db


def create_e2e_alert(alert_id: str = "alt-e2e-1", level: int = 12) -> SiemAlert:
    return SiemAlert(
        id=alert_id,
        rule_id="5710",
        level=level,
        description="Active Kerberoasting Credential Theft",
        src_ip="198.51.100.77",
        agent_name="workstation-99.corp.internal",
        full_log="Kerberoasting ticket request detected from 198.51.100.77 against SPN MSSQLSvc",
    )


def create_base_report(alert: SiemAlert) -> InvestigationReport:
    return InvestigationReport(
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
            summary="Attacker executing Kerberoasting against domain SPNs",
            recommended_actions=["Revoke credentials", "Isolate endpoint"],
        ),
        evidence=Evidence(
            alert=alert,
            agent_name=alert.agent_name,
            threat_intel="Known malicious IP",
            context_notes="Multiple ticket requests",
        ),
    )


@pytest.mark.anyio
async def test_t_e2e_1_complete_happy_path(temp_db):
    """T-E2E-1: Alert -> Stitching -> Base Investigation -> Matched Workflow -> Gap-filling -> Claim & Graph."""
    alert = create_e2e_alert("alt-e2e-happy-1", level=12)
    base_report = create_base_report(alert)

    agent = MagicMock()
    agent.investigate = AsyncMock(return_value=base_report)

    notifier = MagicMock()
    notifier.notify = AsyncMock(return_value=True)

    ticket_store = MagicMock()
    ticket_store.create_ticket = AsyncMock(return_value="TICK-E2E-100")

    policy_engine = MagicMock()
    policy_engine.evaluate = MagicMock(return_value=base_report.policy)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )

    wf_repo = SqliteWorkflowRepository(temp_db)
    claim_repo = SqliteAlertClaimRepository(temp_db)
    org_id = "org-e2e-happy"

    # Enabled workflow with trigger, condition, and tool_slack
    wf = Workflow(
        id="wf-happy-flow",
        name="Kerberoasting Response Playbook",
        enabled=True,
        priority=10,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 10}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#soc-incidents"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    final_report = await runner.process_alert(alert, org_id)

    # 1. Base investigation ran
    assert agent.investigate.call_count == 1
    assert final_report.alert_id == alert.id
    assert final_report.campaign_id is not None

    # 2. Workflow executed and ran node n3 (slack)
    run_repo = SqliteWorkflowRunRepository(temp_db)
    runs = run_repo.list_for_org(org_id)
    assert len(runs) == 1
    assert runs[0]["status"] == "COMPLETED"
    assert runs[0]["outcome"] == "HANDLED"

    # 3. Gap-filling created ticket since workflow did not include tool_jira
    assert ticket_store.create_ticket.call_count == 1

    # 4. Notification was sent exactly once by tool_slack (not duplicated by gap-filler)
    assert notifier.notify.call_count == 1

    # 5. Alert claim recorded as COMPLETED / HANDLED
    claim = claim_repo.get_claim(org_id, alert.id)
    assert claim is not None
    assert claim["status"] == "COMPLETED"
    assert claim["outcome"] == "HANDLED"


@pytest.mark.anyio
async def test_t_e2e_2_approval_gate_and_resume_lifecycle(temp_db):
    """T-E2E-2: Workflow pauses on condition_approval, resumes on admin approval, executes containment."""
    alert = create_e2e_alert("alt-e2e-apprv-1", level=14)
    base_report = create_base_report(alert)

    agent = MagicMock()
    agent.investigate = AsyncMock(return_value=base_report)

    notifier = MagicMock()
    notifier.notify = AsyncMock(return_value=True)

    ticket_store = MagicMock()
    ticket_store.create_ticket = AsyncMock(return_value="TICK-E2E-200")

    policy_engine = MagicMock()
    policy_engine.evaluate = MagicMock(return_value=base_report.policy)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )

    wf_repo = SqliteWorkflowRepository(temp_db)
    approval_repo = SqliteApprovalRepository(temp_db)
    run_repo = SqliteWorkflowRunRepository(temp_db)
    workflow_engine = WorkflowEngine(db=temp_db)
    org_id = "org-e2e-approval"

    # Containment workflow gated by human approval (D11)
    wf = Workflow(
        id="wf-approval-lifecycle",
        name="Critical Isolation Gate Playbook",
        enabled=True,
        priority=10,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 10}),
            WorkflowNode(id="n2", type="condition_approval", config={"required_role": "admin", "prompt_message": "Approve host isolation"}),
            WorkflowNode(id="n3", type="tool_isolate", config={"force_override": False}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    await runner.process_alert(alert, org_id)

    # 1. Workflow should be in WAITING_APPROVAL state
    runs = run_repo.list_for_org(org_id)
    assert len(runs) == 1
    run_record = runs[0]
    assert run_record["status"] == "WAITING_APPROVAL"
    assert run_record["outcome"] == "WAITING_APPROVAL"

    # 2. Check pending approval in repository
    pending_list = approval_repo.list_pending(org_id)
    assert len(pending_list) == 1
    apprv = pending_list[0]
    assert apprv["required_role"] == "admin"
    assert apprv["status"] == "PENDING"

    # 3. Resolve approval as APPROVED
    approval_repo.resolve_approval(org_id, apprv["approval_id"], "APPROVED", resolved_by="admin@corp.internal")

    # 4. Resume run
    resumed_ctx = await workflow_engine.resume_run(
        run_id=run_record["run_id"],
        org_id=org_id,
        deployment=deployment,
        approver="admin@corp.internal",
    )

    assert resumed_ctx is not None
    assert resumed_ctx.status == "COMPLETED"
    assert resumed_ctx.outcome == "HANDLED"
    assert resumed_ctx.side_effects_executed is True
    assert "n3" in resumed_ctx.executed_nodes
    assert resumed_ctx.node_statuses["n3"] == "SUCCESS"


@pytest.mark.anyio
async def test_t_e2e_3_guardrail_block_routes_to_on_error(temp_db):
    """T-E2E-3: Containment targeting protected hostname is blocked by guardrail and routed to on_error."""
    # Target protected domain controller
    alert = SiemAlert(
        id="alt-e2e-block-1",
        rule_id="5710",
        level=14,
        description="Ransomware on Domain Controller",
        agent_name="dc01.corp.internal",  # Critical protected host pattern
        src_ip="10.0.0.5",
    )
    base_report = create_base_report(alert)

    agent = MagicMock()
    agent.investigate = AsyncMock(return_value=base_report)

    notifier = MagicMock()
    notifier.notify = AsyncMock(return_value=True)

    ticket_store = MagicMock()
    ticket_store.create_ticket = AsyncMock(return_value="TICK-E2E-300")

    policy_engine = MagicMock()
    policy_engine.evaluate = MagicMock(return_value=base_report.policy)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )

    wf_repo = SqliteWorkflowRepository(temp_db)
    run_repo = SqliteWorkflowRunRepository(temp_db)
    org_id = "org-e2e-guardrail"

    # Workflow with containment and error handling branch
    wf = Workflow(
        id="wf-guardrail-test",
        name="Guarded Containment Playbook",
        enabled=True,
        priority=10,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 10}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 12}),
            WorkflowNode(id="n3", type="tool_isolate", config={"force_override": False}),
            WorkflowNode(id="n4_error", type="tool_slack", config={"channel": "#containment-blocked"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
            WorkflowEdge(id="e3", source="n3", target="n4_error", source_handle="on_error"),
        ],
    )
    wf_repo.save_workflow(org_id, wf)

    runner = PipelineRunner(deployment=deployment, db=temp_db)
    await runner.process_alert(alert, org_id)

    runs = run_repo.list_for_org(org_id)
    assert len(runs) == 1
    run_record = runs[0]

    # Run ended in FAILED with outcome FAILED_AFTER_SIDE_EFFECTS since on_error executed tool_slack (D7, D10)
    assert run_record["status"] == "FAILED"
    assert run_record["outcome"] == "FAILED_AFTER_SIDE_EFFECTS"
    assert run_record["side_effects_executed"] is True

    # Node trace shows n3 BLOCKED and n4_error executed via on_error
    node_runs = run_repo.get_node_runs(org_id, run_record["run_id"])
    node_status_map = {nr["node_id"]: nr["status"] for nr in node_runs}
    assert node_status_map.get("n3") == "BLOCKED"
    assert node_status_map.get("n4_error") == "SUCCESS"
