from __future__ import annotations

from pathlib import Path

import pytest

from terminus.models import SiemAlert
from terminus.pipeline.validation import validate_workflow
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.service.sensor import ServiceConnectionSensor, _seed_workflows
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAgentRepository,
    SqliteAllowlistRepository,
    SqliteWorkflowRepository,
)


class NoOutboundDeployment:
    class Notifier:
        def __init__(self) -> None:
            self.calls = 0

        async def notify(self, report, org_id) -> None:
            self.calls += 1

    class Tickets:
        async def create_ticket(self, report, org_id):
            raise AssertionError("dry-run must not create tickets")

    def __init__(self) -> None:
        self.notifier = self.Notifier()
        self.ticket_store = self.Tickets()
        self.agent = None


def _repos(tmp_path: Path):
    db = Database(str(tmp_path / "sensor-workflows.db"))
    return (
        db,
        SqliteAgentRepository(db),
        SqliteWorkflowRepository(db),
        SqliteAllowlistRepository(db),
    )


def _alert(level: int = 12, host: str = "workstation-102") -> SiemAlert:
    return SiemAlert(
        id=f"alert-{level}",
        rule_id=1001,
        level=level,
        description="Ransomware activity detected",
        agent_name=host,
        src_ip="198.51.100.25",
    )


def test_fresh_sensor_workflows_are_valid_and_have_graph_metadata(tmp_path: Path):
    _db, agents, workflows, allowlist = _repos(tmp_path)
    ServiceConnectionSensor().auto_configure_baseline("org-fresh", agents, workflows, allowlist)

    seeded = workflows.list_for_org("org-fresh")
    assert {wf.id for wf in seeded} == {"wf-slack-triage", "wf-ransomware-containment"}
    for workflow in seeded:
        assert validate_workflow(workflow) == []
        assert all(node.label for node in workflow.nodes)
        assert len({(node.x, node.y) for node in workflow.nodes}) == len(workflow.nodes)

    slack = next(wf for wf in seeded if wf.id == "wf-slack-triage")
    severity_edge = next(edge for edge in slack.edges if edge.source == "n2")
    assert severity_edge.source_handle == "true"


@pytest.mark.anyio
async def test_fresh_seed_dry_runs_take_slack_and_approval_containment_paths(tmp_path: Path):
    db, agents, workflows, allowlist = _repos(tmp_path)
    ServiceConnectionSensor().auto_configure_baseline("org-fresh", agents, workflows, allowlist)
    seeded = {wf.id: wf for wf in workflows.list_for_org("org-fresh")}
    engine = WorkflowEngine(db=db)
    deployment = NoOutboundDeployment()

    slack_ctx = await engine.execute_workflow(
        workflow=seeded["wf-slack-triage"],
        alert=_alert(level=12),
        org_id="org-fresh",
        deployment=deployment,
        dry_run=True,
    )
    assert slack_ctx.node_statuses["n3"] == "SUCCESS"
    assert slack_ctx.node_outputs["n3"]["dry_run"] is True
    assert deployment.notifier.calls == 0
    assert slack_ctx.side_effects_executed is False

    containment = seeded["wf-ransomware-containment"]
    assert validate_workflow(containment) == []
    approval_cfg = next(node.config for node in containment.nodes if node.type == "condition_approval")
    assert approval_cfg == {
        "required_role": "admin",
        "prompt_message": "Approve simulated workstation isolation for this ransomware alert.",
        "timeout_seconds": 300,
    }
    containment_ctx = await engine.execute_workflow(
        workflow=containment,
        alert=_alert(level=12),
        org_id="org-fresh",
        deployment=deployment,
        dry_run=True,
    )
    assert containment_ctx.node_outputs["n3"]["dry_run_approved"] is True
    assert containment_ctx.node_statuses["n4"] == "SUCCESS"
    assert containment_ctx.node_outputs["n4"]["simulated"] is True
    assert containment_ctx.node_outputs["n4"]["executed"] is False
    assert containment_ctx.node_outputs["n4"]["verified"] is False
    assert containment_ctx.node_statuses["n5"] == "SUCCESS"
    assert deployment.notifier.calls == 0
    assert containment_ctx.side_effects_executed is False


def test_auto_config_upgrades_only_exact_legacy_seed_graphs(tmp_path: Path):
    _db, agents, workflows, allowlist = _repos(tmp_path)
    _, legacy = _seed_workflows("legacy")
    for wf in legacy:
        workflows.save(wf, "org-existing")

    edited = workflows.get("wf-slack-triage", "org-existing")
    edited.nodes[1].config["min_level"] = 8
    workflows.save(edited, "org-existing")
    edited_version = workflows.get("wf-slack-triage", "org-existing").version

    ServiceConnectionSensor().auto_configure_baseline("org-existing", agents, workflows, allowlist)

    upgraded = workflows.get("wf-ransomware-containment", "org-existing")
    assert upgraded.version == 2
    assert validate_workflow(upgraded) == []
    preserved = workflows.get("wf-slack-triage", "org-existing")
    assert preserved.version == edited_version
    assert preserved.nodes[1].config["min_level"] == 8
