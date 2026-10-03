import pytest
from pathlib import Path

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
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import init_db
from terminus.ticketing.memory import MemoryTickets


class FakeNotifier:
    def __init__(self):
        self.sent = []

    async def notify(self, report, org_id):
        self.sent.append({"report": report, "org_id": str(org_id)})


class FakeDeployment:
    def __init__(self):
        self.notifier = FakeNotifier()
        self.ticket_store = MemoryTickets()
        self.agent = None


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "phase4_engine.db"
    init_db(db_file)
    return db_file


def make_sample_alert(alert_id: str = "alt-01", level: int = 12, host: str = "web-srv-01") -> SiemAlert:
    return SiemAlert(
        id=alert_id,
        rule_id=1001,
        level=level,
        description="SSH brute force attempt",
        location="/var/log/auth.log",
        agent_name=host,
        src_ip="198.51.100.25",
    )


def make_sample_report(alert: SiemAlert) -> InvestigationReport:
    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(
            alert_id=alert.id,
            tier=Tier.TRIAGE,
            should_investigate=True,
            reason="Policy triage rule matched",
        ),
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Confirmed brute force attack",
            recommended_actions=["Isolate host", "Block source IP"],
        ),
        evidence=Evidence(
            alert=alert,
            agent_name=alert.agent_name,
            threat_intel="Known malicious IP",
            context_notes="Sample context notes",
        ),
    )


@pytest.mark.anyio
async def test_t_eng_1_happy_path_linear(test_db):
    """T-ENG-1: Happy path linear workflow execution."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=12)
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-linear",
        name="Linear Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-linear",
        deployment=deployment,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.outcome == "HANDLED"
    assert "n1" in ctx.executed_nodes
    assert "n2" in ctx.executed_nodes
    assert "n3" in ctx.executed_nodes
    assert ctx.node_statuses["n3"] == "SUCCESS"
    assert ctx.side_effects_executed is True
    assert "slack" in ctx.notified


@pytest.mark.anyio
async def test_t_eng_2_condition_branching(test_db):
    """T-ENG-2: Condition severity branching (true vs false path)."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=7)  # Below min_level 10
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-branch",
        name="Branching Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3_true", type="tool_slack", config={"channel": "#critical"}),
            WorkflowNode(id="n3_false", type="tool_slack", config={"channel": "#triage"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3_true", source_handle="true"),
            WorkflowEdge(id="e3", source="n2", target="n3_false", source_handle="false"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-branch",
        deployment=deployment,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.node_statuses["n3_false"] == "SUCCESS"
    assert ctx.node_statuses["n3_true"] == "SKIPPED"


@pytest.mark.anyio
async def test_t_eng_3_join_semantics(test_db):
    """T-ENG-3: Join semantics (D9): node runs if >= 1 LIVE incoming edge; skipped if all DEAD."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=12)
    report = make_sample_report(alert)

    # Both n2a (min_lvl 10 -> TRUE) and n2b (min_lvl 15 -> FALSE) point to n3
    wf = Workflow(
        id="wf-join",
        name="Join Semantics Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2a", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n2b", type="condition_severity", config={"min_level": 15}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2a", source_handle="default"),
            WorkflowEdge(id="e2", source="n1", target="n2b", source_handle="default"),
            WorkflowEdge(id="e3", source="n2a", target="n3", source_handle="true"),
            WorkflowEdge(id="e4", source="n2b", target="n3", source_handle="true"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-join",
        deployment=deployment,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.node_statuses["n2a"] == "SUCCESS"
    assert ctx.node_statuses["n2b"] == "SUCCESS"
    assert ctx.edge_states["e3"] == "LIVE"
    assert ctx.edge_states["e4"] == "DEAD"
    # Because e3 is LIVE (>= 1 live incoming edge), n3 runs!
    assert ctx.node_statuses["n3"] == "SUCCESS"


@pytest.mark.anyio
async def test_t_eng_4_trigger_mismatch(test_db):
    """T-ENG-4: Trigger mismatch marks default edges DEAD and skips downstream."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=3)  # Trigger requires min_level 10
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-trig-miss",
        name="Trigger Mismatch",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 10}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-trig",
        deployment=deployment,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.node_statuses["n1"] == "SUCCESS"
    assert ctx.edge_states["e1"] == "DEAD"
    assert ctx.node_statuses["n2"] == "SKIPPED"


@pytest.mark.anyio
async def test_t_eng_5_and_6_approval_gate_and_resume(test_db):
    """T-ENG-5 & T-ENG-6: Approval pauses run; resume with approve executes containment."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=12, host="compromised-srv-01")
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-apprv",
        name="Approval Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_approval", config={"required_role": "admin"}),
            WorkflowNode(id="n3", type="tool_isolate", config={"force_override": False}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )

    # 1. Initial execution pauses at approval gate (T-ENG-5)
    ctx1 = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-apprv",
        deployment=deployment,
    )

    assert ctx1.status == "WAITING_APPROVAL"
    assert ctx1.outcome == "WAITING_APPROVAL"
    assert ctx1.node_statuses["n2"] == "WAITING_APPROVAL"
    assert "n3" not in ctx1.executed_nodes
    assert len(ctx1.pending_approvals) == 1
    approval_id = ctx1.pending_approvals[0]["approval_id"]

    # 2. Resolve approval in repository
    engine.approval_repo.resolve_approval(
        "org-apprv",
        approval_id,
        status="APPROVED",
        resolved_by="user:admin@terminus.local",
    )

    # 3. Resume run (T-ENG-6)
    ctx2 = await engine.resume_run(
        run_id=ctx1.run_id,
        org_id="org-apprv",
        deployment=deployment,
        approver="user:admin@terminus.local",
    )

    assert ctx2 is not None
    assert ctx2.status == "COMPLETED"
    assert ctx2.outcome == "HANDLED"
    assert ctx2.node_statuses["n3"] == "SUCCESS"
    assert ctx2.side_effects_executed is True


@pytest.mark.anyio
async def test_t_eng_7_approval_rejection_resume(test_db):
    """T-ENG-7: Rejection resume makes false path LIVE and bypasses containment."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=12, host="compromised-srv-01")
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-apprv-rej",
        name="Approval Rejection Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_approval", config={"required_role": "admin"}),
            WorkflowNode(id="n3_iso", type="tool_isolate", config={"force_override": False}),
            WorkflowNode(id="n3_slack", type="tool_slack", config={"channel": "#rejected"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3_iso", source_handle="true"),
            WorkflowEdge(id="e3", source="n2", target="n3_slack", source_handle="false"),
        ],
    )

    ctx1 = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-rej",
        deployment=deployment,
    )
    assert ctx1.status == "WAITING_APPROVAL"
    approval_id = ctx1.pending_approvals[0]["approval_id"]

    # Reject approval
    engine.approval_repo.resolve_approval(
        "org-rej",
        approval_id,
        status="REJECTED",
        resolved_by="user:admin@terminus.local",
    )

    ctx2 = await engine.resume_run(
        run_id=ctx1.run_id,
        org_id="org-rej",
        deployment=deployment,
        approver="user:admin@terminus.local",
    )

    assert ctx2 is not None
    assert ctx2.status == "COMPLETED"
    assert ctx2.node_statuses["n3_iso"] == "SKIPPED"
    assert ctx2.node_statuses["n3_slack"] == "SUCCESS"


@pytest.mark.anyio
async def test_t_eng_8_containment_guardrail_block(test_db):
    """T-ENG-8: Containment on protected target is BLOCKED by guardrail, triggering on_error."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    # Target in protected network 10.0.0.0/24
    alert = SiemAlert(
        id="alt-prot",
        rule_id=1001,
        level=12,
        description="Protected subnet hit",
        src_ip="10.0.0.5",
        agent_name="dc-prod-01",
    )
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-guardrail",
        name="Guardrail Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_firewall", config={"ip_address": "10.0.0.5"}),
            WorkflowNode(id="n4_err", type="tool_slack", config={"channel": "#guardrail-alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
            WorkflowEdge(id="e3", source="n3", target="n4_err", source_handle="on_error"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-grd",
        deployment=deployment,
    )

    assert ctx.status == "FAILED"
    assert ctx.node_statuses["n3"] == "BLOCKED"
    assert ctx.node_statuses["n4_err"] == "SUCCESS"
    assert any("guardrail" in e.lower() for e in ctx.errors)


@pytest.mark.anyio
async def test_t_eng_9_containment_force_override(test_db):
    """T-ENG-9: Containment force_override bypasses critical hostname check."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(host="dc-primary-prod")
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-override",
        name="Force Override Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_isolate", config={"hostname": "dc-primary-prod", "force_override": True}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-ovr",
        deployment=deployment,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.node_statuses["n3"] == "SUCCESS"


@pytest.mark.anyio
async def test_t_eng_10_dry_run_execution(test_db):
    """T-ENG-10: Dry run runs in-memory without mutating repository or side-effects."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert()
    report = make_sample_report(alert)

    wf = Workflow(
        id="wf-dry",
        name="Dry Run Test",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-dry",
        deployment=deployment,
        dry_run=True,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.dry_run is True
    # Verify nothing was saved to DB
    stored_run = engine.run_repo.get_run("org-dry", ctx.run_id)
    assert stored_run is None


@pytest.mark.anyio
async def test_t_eng_11_agent_llm_persona_reinvestigation(test_db):
    """T-ENG-11: agent_llm node replaces verdict in dry-run/live while preserving policy."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert()
    report = make_sample_report(alert)
    orig_policy = report.policy

    wf = Workflow(
        id="wf-llm",
        name="Agent LLM Flow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="agent_llm", config={"persona_instructions": "Focus on root cause"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-llm",
        deployment=deployment,
        dry_run=True,
    )

    assert ctx.status == "COMPLETED"
    assert ctx.report.policy == orig_policy
    assert ctx.node_statuses["n2"] == "SUCCESS"


@pytest.mark.anyio
async def test_t_eng_12_outcome_mapping(test_db):
    """T-ENG-12: Status vs Outcome mapping (D7)."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert()
    report = make_sample_report(alert)

    # 1. Failure before side effects -> FAILED_BEFORE_SIDE_EFFECTS
    wf_fail_before = Workflow(
        id="wf-fail-before",
        name="Fail Before",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="unknown_node_type", config={}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    ctx1 = await engine.execute_workflow(
        workflow=wf_fail_before,
        alert=alert,
        base_report=report,
        org_id="org-map",
        deployment=deployment,
    )
    assert ctx1.status == "FAILED"
    assert ctx1.outcome == "FAILED_BEFORE_SIDE_EFFECTS"

    # 2. Failure after side effects -> FAILED_AFTER_SIDE_EFFECTS
    wf_fail_after = Workflow(
        id="wf-fail-after",
        name="Fail After",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#alerts"}),
            WorkflowNode(id="n3", type="unknown_node_type", config={}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="default"),
        ],
    )
    ctx2 = await engine.execute_workflow(
        workflow=wf_fail_after,
        alert=alert,
        base_report=report,
        org_id="org-map",
        deployment=deployment,
    )
    assert ctx2.status == "FAILED"
    assert ctx2.outcome == "FAILED_AFTER_SIDE_EFFECTS"


@pytest.mark.anyio
async def test_t_eng_13_engine_never_raises(test_db):
    """T-ENG-13: Engine never raises exceptions during workflow execution (D6)."""
    engine = WorkflowEngine()
    alert = make_sample_alert()
    report = make_sample_report(alert)

    # Malformed deployment (None)
    wf = Workflow(
        id="wf-robust",
        name="Robustness Test",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )

    ctx = await engine.execute_workflow(
        workflow=wf,
        alert=alert,
        base_report=report,
        org_id="org-robust",
        deployment=None,  # Passing None to test exception handling
    )

    assert isinstance(ctx.errors, list)
    assert ctx.status == "FAILED"


@pytest.mark.anyio
async def test_t_eng_14_definition_snapshot_concurrency(test_db):
    """T-ENG-14: Concurrency and versioning snapshot invariance (D18)."""
    engine = WorkflowEngine()
    deployment = FakeDeployment()
    alert = make_sample_alert(level=12, host="host-snap")
    report = make_sample_report(alert)

    wf_v1 = Workflow(
        id="wf-snap",
        name="Snapshot Flow v1",
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_approval", config={"required_role": "admin"}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#v1-channel"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )

    ctx1 = await engine.execute_workflow(
        workflow=wf_v1,
        alert=alert,
        base_report=report,
        org_id="org-snap",
        deployment=deployment,
    )
    assert ctx1.status == "WAITING_APPROVAL"
    approval_id = ctx1.pending_approvals[0]["approval_id"]

    # Approve
    engine.approval_repo.resolve_approval(
        "org-snap",
        approval_id,
        status="APPROVED",
        resolved_by="user:admin@terminus.local",
    )

    # Resume must use snapshot from v1
    ctx2 = await engine.resume_run(
        run_id=ctx1.run_id,
        org_id="org-snap",
        deployment=deployment,
        approver="user:admin@terminus.local",
    )

    assert ctx2 is not None
    assert ctx2.status == "COMPLETED"
    assert ctx2.node_statuses["n3"] == "SUCCESS"
    assert ctx2.node_outputs["n3"]["channel"] == "#v1-channel"
