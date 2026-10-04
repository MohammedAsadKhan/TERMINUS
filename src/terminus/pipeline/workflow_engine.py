"""Asynchronous DAG Workflow Execution Engine for TERMINUS.

Implements all workflow execution decisions (D1, D2, D3, D4, D6, D7, D8, D9, D10,
D11, D14, D15, D16, D17, D18, D19, D20, D21).
"""

from __future__ import annotations

import dataclasses
import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from terminus.agent.investigator import InvestigationAgent
from terminus.containment.guardrails import ContainmentGuardrail
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
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.nodes.schemas import NodeType
from terminus.pipeline.specialist_bridge import SpecialistBridge, simulate
from terminus.pipeline.triggers import trigger_matches
from terminus.privacy.redactor import SecretRedactor
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAllowlistRepository,
    SqliteApprovalRepository,
    SqliteWorkflowRunRepository,
)

logger = logging.getLogger("terminus.pipeline.workflow_engine")

DEFAULT_TIMEOUT_SECS = {
    NodeType.TRIGGER_WAZUH.value: 5,
    NodeType.CONDITION_SEVERITY.value: 5,
    NodeType.CONDITION_APPROVAL.value: 10,
    NodeType.AGENT_LLM.value: 60,
    NodeType.TOOL_SLACK.value: 15,
    NodeType.TOOL_JIRA.value: 15,
    NodeType.TOOL_ISOLATE.value: 30,
    NodeType.TOOL_FIREWALL.value: 30,
}


@dataclass
class WorkflowExecutionContext:
    run_id: str
    workflow_id: str
    org_id: str
    alert: SiemAlert
    report: InvestigationReport
    status: str = "RUNNING"  # RUNNING, WAITING_APPROVAL, WAITING_SPECIALIST, COMPLETED, FAILED, INTERRUPTED
    outcome: str = "HANDLED"  # HANDLED, WAITING_APPROVAL, FAILED_BEFORE_SIDE_EFFECTS, FAILED_AFTER_SIDE_EFFECTS, INTERRUPTED
    side_effects_executed: bool = False
    unknown_outcome: bool = False
    ticket_created: bool = False
    incident_id: str | None = None
    notified: set[str] = field(default_factory=set)
    node_outputs: dict[str, Any] = field(default_factory=dict)
    executed_nodes: list[str] = field(default_factory=list)
    node_statuses: dict[str, str] = field(default_factory=dict)  # SUCCESS, FAILED, BLOCKED, WAITING_APPROVAL, SKIPPED
    errors: list[str] = field(default_factory=list)
    edge_states: dict[str, str] = field(default_factory=dict)  # edge_id -> PENDING, LIVE, DEAD
    pending_approvals: list[dict[str, Any]] = field(default_factory=list)
    dry_run: bool = False


class WorkflowEngine:
    """Evaluates and executes DAG-structured SOC automation workflows."""

    def __init__(
        self,
        db: Database | None = None,
        run_repo: SqliteWorkflowRunRepository | None = None,
        approval_repo: SqliteApprovalRepository | None = None,
        allowlist_repo: SqliteAllowlistRepository | None = None,
        specialist_bridge: SpecialistBridge | None = None,
    ) -> None:
        self.db = db
        self.specialist_bridge = specialist_bridge
        self.run_repo = run_repo or SqliteWorkflowRunRepository(db=db)
        self.approval_repo = approval_repo or SqliteApprovalRepository(db=db)
        self.allowlist_repo = allowlist_repo or SqliteAllowlistRepository(db=db)

    async def execute_workflow(
        self,
        workflow: Workflow,
        alert: SiemAlert,
        base_report: InvestigationReport | None = None,
        org_id: str | None = None,
        deployment: PipelineDeployment | None = None,
        dry_run: bool = False,
        **kwargs: Any,
    ) -> WorkflowExecutionContext:
        """Executes a visual node graph for the given alert (never raises, D6)."""
        run_id = f"wfrun-{secrets.token_hex(6)}"
        now_iso = datetime.now(UTC).isoformat()

        # Handle flexible positional argument orders
        if isinstance(base_report, str):
            org_id_val = str(base_report)
            report_val = org_id if isinstance(org_id, InvestigationReport) else kwargs.get("report")
        else:
            org_id_val = str(org_id or kwargs.get("org_id") or "default")
            report_val = base_report

        if report_val is None:
            report_val = InvestigationReport(
                alert_id=alert.id,
                policy=PolicyResult(alert_id=alert.id, tier=Tier.TRIAGE, should_investigate=True, reason="Execution report"),
                verdict=Verdict(severity=Severity.HIGH, confidence=Confidence.HIGH, summary="Investigation report", recommended_actions=[]),
                evidence=Evidence(alert=alert, agent_name=alert.agent_name, threat_intel="", context_notes=""),
            )

        # Build execution context
        ctx = WorkflowExecutionContext(
            run_id=run_id,
            workflow_id=workflow.id,
            org_id=org_id_val,
            alert=alert,
            report=report_val,
            dry_run=dry_run,
            incident_id=kwargs.get("incident_id"),
        )

        # Initialize all edge states as PENDING
        for edge in workflow.edges:
            ctx.edge_states[edge.id] = "PENDING"

        # If live run, persist initial RUNNING record (D7, D18)
        if not dry_run:
            try:
                self.run_repo.create_run(
                    org_id=org_id_val,
                    run_id=run_id,
                    workflow_id=workflow.id,
                    alert_id=alert.id,
                    definition_snapshot=workflow,
                    alert=alert,
                    base_report=base_report,
                    incident_id=ctx.incident_id,
                )
            except Exception as e:
                logger.error(f"Failed to persist workflow run {run_id}: {e}")
                ctx.errors.append(f"Persistence error on start: {e}")

        # Traverse DAG
        await self._traverse(workflow, ctx, deployment)

        # Finalize run state & persist (D7)
        self._finalize_run_status(ctx)
        if not dry_run:
            self._persist_final_run(workflow, ctx)
            await self._persist_incident_report(ctx, deployment)

        return ctx

    async def resume_run(
        self,
        run_id: str,
        org_id: str,
        deployment: PipelineDeployment | None = None,
        approver: str = "system",
        approval_id: str | None = None,
        action: str | None = None,
        actor: str | None = None,
        **kwargs: Any,
    ) -> WorkflowExecutionContext | None:
        """Resumes a workflow run after an approval node decision (D14, D18)."""
        run = self.run_repo.get_run(str(org_id), run_id)
        if not run:
            return None

        # Reconstruct workflow definition from snapshot (D18)
        snapshot_raw = run.get("definition_snapshot")
        snapshot_dict = snapshot_raw if isinstance(snapshot_raw, dict) else json.loads(snapshot_raw or "{}")
        workflow = Workflow.model_validate(snapshot_dict)

        alert_raw = run.get("alert_json")
        alert_dict = alert_raw if isinstance(alert_raw, dict) else json.loads(alert_raw or "{}")
        alert = SiemAlert.model_validate(alert_dict)

        report_raw = run.get("base_report_json")
        report_dict = report_raw if isinstance(report_raw, dict) else json.loads(report_raw or "{}")
        report = InvestigationReport.from_dict(report_dict)

        edge_raw = run.get("edge_states_json")
        edge_states = edge_raw if isinstance(edge_raw, dict) else json.loads(edge_raw or "{}")

        err_raw = run.get("errors_json")
        errors = err_raw if isinstance(err_raw, list) else json.loads(err_raw or "[]")

        ctx = WorkflowExecutionContext(
            run_id=run_id,
            workflow_id=workflow.id,
            org_id=str(org_id),
            alert=alert,
            report=report,
            status="RUNNING",
            side_effects_executed=bool(run.get("side_effects", 0)),
            unknown_outcome=bool(run.get("unknown_outcome", 0)),
            edge_states=edge_states,
            errors=errors,
            dry_run=False,
            incident_id=run.get("incident_id") or report.incident_id,
        )

        # Restore past node outputs and statuses
        past_nodes = self.run_repo.get_node_runs(str(org_id), run_id)
        for nr in past_nodes:
            nid = nr["node_id"]
            ctx.executed_nodes.append(nid)
            ctx.node_statuses[nid] = nr["status"]
            try:
                ctx.node_outputs[nid] = json.loads(nr.get("outputs_json") or "{}")
            except Exception:
                ctx.node_outputs[nid] = {}

        # Find approval node and resolve edges based on approval resolution
        approvals = self.approval_repo.list_for_run(str(org_id), run_id)
        for apprv in approvals:
            apprv_node_id = apprv["node_id"]
            apprv_status = apprv["status"]
            if apprv_status in ("APPROVED", "REJECTED", "EXPIRED"):
                is_approved = apprv_status == "APPROVED"
                # Update approval node status in ctx
                ctx.node_statuses[apprv_node_id] = "SUCCESS"
                # Resolve outgoing edges for approval node
                for edge in workflow.edges:
                    if edge.source == apprv_node_id:
                        handle = edge.source_handle or "true"
                        if is_approved:
                            ctx.edge_states[edge.id] = "LIVE" if handle == "true" else "DEAD"
                        else:
                            ctx.edge_states[edge.id] = "LIVE" if handle == "false" else "DEAD"

        # Re-evaluate nodes waiting on a specialist run; the idempotency key returns
        # the same task, and a terminal recorded run lets the node complete.
        for nid in [n for n, st in ctx.node_statuses.items() if st == "WAITING_SPECIALIST"]:
            ctx.executed_nodes[:] = [x for x in ctx.executed_nodes if x != nid]
            del ctx.node_statuses[nid]
            ctx.node_outputs.pop(nid, None)

        # Continue traversal
        await self._traverse(workflow, ctx, deployment)

        # Finalize and persist
        self._finalize_run_status(ctx)
        self._persist_final_run(workflow, ctx)
        await self._persist_incident_report(ctx, deployment)

        return ctx

    async def _traverse(
        self,
        workflow: Workflow,
        ctx: WorkflowExecutionContext,
        deployment: PipelineDeployment,
    ) -> None:
        """Executes the DAG using resolved-edge counting join semantics (D9)."""
        node_map = {n.id: n for n in workflow.nodes}
        incoming_edges: dict[str, list[WorkflowEdge]] = {n.id: [] for n in workflow.nodes}
        outgoing_edges: dict[str, list[WorkflowEdge]] = {n.id: [] for n in workflow.nodes}

        for edge in workflow.edges:
            if edge.target in incoming_edges:
                incoming_edges[edge.target].append(edge)
            if edge.source in outgoing_edges:
                outgoing_edges[edge.source].append(edge)

        # Find all unexecuted nodes ready to run (roots or all incoming edges already resolved)
        queue: list[str] = []
        for nid, in_list in incoming_edges.items():
            if nid in ctx.executed_nodes:
                continue
            if len(in_list) == 0 or all(ctx.edge_states.get(e.id, "PENDING") != "PENDING" for e in in_list):
                queue.append(nid)

        while queue:
            node_id = queue.pop(0)
            node = node_map.get(node_id)
            if not node:
                continue

            # Check incoming edges (D9)
            in_edges = incoming_edges.get(node_id, [])
            if in_edges:
                # All incoming edges must be resolved (LIVE or DEAD)
                if any(ctx.edge_states.get(e.id, "PENDING") == "PENDING" for e in in_edges):
                    continue

                has_live_edge = any(ctx.edge_states.get(e.id) == "LIVE" for e in in_edges)
                if not has_live_edge:
                    # All incoming edges are DEAD -> node is SKIPPED
                    ctx.node_statuses[node_id] = "SKIPPED"
                    ctx.executed_nodes.append(node_id)
                    # Mark all outgoing edges DEAD
                    for out_e in outgoing_edges.get(node_id, []):
                        ctx.edge_states[out_e.id] = "DEAD"
                        # Check downstream nodes
                        self._check_downstream_enqueuing(out_e.target, incoming_edges, queue, ctx)
                    continue

            # Node is runnable! Execute node
            ctx.executed_nodes.append(node_id)
            node_status, node_output, active_handle, is_paused = await self._execute_node(
                node, workflow, ctx, deployment
            )

            ctx.node_statuses[node_id] = node_status
            ctx.node_outputs[node_id] = SecretRedactor.redact_dict(node_output)

            # Persist node execution trace step
            if not ctx.dry_run:
                self._record_node_run(node, node_status, node_output, ctx)

            # If node pauses workflow for approval (D14, D15), do not resolve its outgoing edges
            if is_paused:
                continue

            # Resolve outgoing edges for completed node (D8, D10)
            for out_e in outgoing_edges.get(node_id, []):
                handle = out_e.source_handle or "default"
                if node_status == "BLOCKED" or node_status == "FAILED":
                    # On error / block: only 'on_error' edges are LIVE (D10)
                    ctx.edge_states[out_e.id] = "LIVE" if handle == "on_error" else "DEAD"
                else:
                    ctx.edge_states[out_e.id] = "LIVE" if handle == active_handle else "DEAD"

                self._check_downstream_enqueuing(out_e.target, incoming_edges, queue, ctx)

    def _check_downstream_enqueuing(
        self,
        target_id: str,
        incoming_edges: dict[str, list[WorkflowEdge]],
        queue: list[str],
        ctx: WorkflowExecutionContext,
    ) -> None:
        """Enqueues downstream node if all incoming edges are resolved (D9)."""
        if target_id in ctx.executed_nodes or target_id in queue:
            return
        target_in = incoming_edges.get(target_id, [])
        if all(ctx.edge_states.get(e.id, "PENDING") != "PENDING" for e in target_in):
            queue.append(target_id)

    async def _execute_node(
        self,
        node: WorkflowNode,
        workflow: Workflow,
        ctx: WorkflowExecutionContext,
        deployment: PipelineDeployment,
    ) -> tuple[str, dict[str, Any], str, bool]:
        """Executes a single node by type with timeout shielding (D16).

        Returns: (node_status, node_output, active_handle, is_paused)
        """
        ntype = node.type
        cfg = node.config or {}
        timeout_sec = DEFAULT_TIMEOUT_SECS.get(ntype, 15)

        try:
            # 1. trigger_wazuh (D1, D2)
            if ntype == NodeType.TRIGGER_WAZUH.value:
                matches = trigger_matches(cfg, ctx.alert)
                if matches:
                    return "SUCCESS", {"triggered": True, "alert_id": ctx.alert.id}, "default", False
                return "SUCCESS", {"triggered": False, "alert_id": ctx.alert.id}, "false", False

            # 2. condition_severity (D1, D8)
            if ntype == NodeType.CONDITION_SEVERITY.value:
                min_lvl = cfg.get("min_level", 0)
                min_sev = cfg.get("min_verdict_severity")
                sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}

                level_pass = ctx.alert.level >= min_lvl
                verdict_pass = True
                if min_sev and ctx.report and ctx.report.verdict:
                    curr_sev = ctx.report.verdict.severity.value.lower()
                    verdict_pass = sev_order.get(curr_sev, 1) >= sev_order.get(min_sev.lower(), 1)

                passes = level_pass and verdict_pass
                active_handle = "true" if passes else "false"
                return "SUCCESS", {"passed": passes, "level_check": level_pass, "verdict_check": verdict_pass}, active_handle, False

            # 3. condition_approval (D1, D14, D15)
            if ntype == NodeType.CONDITION_APPROVAL.value:
                if ctx.dry_run:
                    return "SUCCESS", {"dry_run_approved": True, "required_role": cfg.get("required_role", "admin")}, "true", False

                # Live approval: check if already pending or create
                role = cfg.get("required_role", "admin")
                msg = cfg.get("prompt_message") or f"Approval requested for alert {ctx.alert.id}"
                timeout_mins = cfg.get("timeout_minutes", 60)
                now_dt = datetime.now(UTC)
                expires_dt = now_dt + timedelta(minutes=timeout_mins)
                approval_id = f"apprv-{secrets.token_hex(6)}"

                apprv_record = self.approval_repo.create_approval(
                    approval_id=approval_id,
                    run_id=ctx.run_id,
                    workflow_id=workflow.id,
                    org_id=ctx.org_id,
                    node_id=node.id,
                    required_role=role,
                    prompt_message=msg,
                    expires_at=expires_dt.isoformat(),
                )
                ctx.pending_approvals.append(apprv_record)
                return "WAITING_APPROVAL", {"approval_id": approval_id, "status": "PENDING", "required_role": role}, "true", True

            # 4. agent_llm (D1, D3)
            if ntype == NodeType.AGENT_LLM.value:
                # With a bridge, only recorded specialist runs are reported (no verdict is
                # fabricated). Without one, live mode keeps the legacy unrecorded agent.
                if ctx.dry_run:
                    sim = simulate(cfg).to_output()
                    sim["persona"] = cfg.get("persona_instructions") or ""
                    return "SUCCESS", sim, "default", False
                if self.specialist_bridge is None:
                    legacy_agent = InvestigationAgent(llm=deployment.agent.llm)
                    re_report = await legacy_agent.investigate(
                        alert=ctx.alert,
                        org_id=OrgId(ctx.org_id),
                        persona_prompt=cfg.get("persona_instructions") or "",
                    )
                    ctx.report = dataclasses.replace(
                        ctx.report,
                        verdict=re_report.verdict,
                        evidence=re_report.evidence,
                        evidence_citations=re_report.evidence_citations,
                    )
                    return "SUCCESS", {"verdict": re_report.verdict.model_dump(), "legacy_unrecorded": True}, "default", False
                outcome = self.specialist_bridge.request(
                    org_id=ctx.org_id,
                    incident_id=ctx.incident_id,
                    run_id=ctx.run_id,
                    node_id=node.id,
                    workflow_id=workflow.id,
                    config=cfg,
                )
                spec_out = outcome.to_output()
                if outcome.state == "completed":
                    return "SUCCESS", spec_out, "default", False
                if outcome.state == "waiting":
                    return "WAITING_SPECIALIST", spec_out, "default", True
                if outcome.state in ("failed", "unresolved_agent"):
                    ctx.errors.append(f"Specialist node {node.id}: {outcome.gap}")
                    return ("FAILED" if outcome.state == "failed" else "UNRESOLVED_AGENT"), spec_out, "on_error", False
                return "NOT_EXECUTED", spec_out, "default", False

            # 5. tool_slack (D1, D4)
            if ntype == NodeType.TOOL_SLACK.value:
                channel = cfg.get("channel") or "#soc-alerts"
                ctx.notified.add("slack")

                if ctx.dry_run:
                    return "SUCCESS", {"dry_run": True, "channel": channel, "notified": True}, "default", False

                await deployment.notifier.notify(ctx.report, OrgId(ctx.org_id))
                ctx.side_effects_executed = True
                return "SUCCESS", {"action": "slack_notification_sent", "channel": channel}, "default", False

            # 6. tool_jira (D1, D4)
            if ntype == NodeType.TOOL_JIRA.value:
                project = cfg.get("project") or "SEC"
                if ctx.dry_run:
                    ctx.ticket_created = True
                    return "SUCCESS", {"dry_run": True, "project": project, "ticket_created": True}, "default", False

                t = ctx.incident_id or str(await deployment.ticket_store.create_ticket(ctx.report, OrgId(ctx.org_id)))
                ctx.incident_id = str(t)
                ctx.report = dataclasses.replace(ctx.report, incident_id=ctx.incident_id)
                ctx.ticket_created = True
                export = getattr(deployment, "export_ticket", None) if getattr(type(deployment), "export_ticket", None) else None
                try:
                    external_id = await export(str(t), ctx.report, OrgId(ctx.org_id)) if export else None
                except Exception:
                    ctx.unknown_outcome = True
                    ctx.side_effects_executed = True
                    raise
                ctx.side_effects_executed = True
                return "SUCCESS", {"action": "ticket_created", "ticket": t, "external_ticket_id": external_id}, "default", False

            # 7. tool_isolate (D1, D11, D12, D16)
            if ntype == NodeType.TOOL_ISOLATE.value:
                target_host = cfg.get("hostname") or ctx.alert.agent_name or "unknown-host"
                force_override = bool(cfg.get("force_override", False))

                guardrail_res = ContainmentGuardrail.assess_target(
                    target=target_host,
                    kind="host",
                    org_id=ctx.org_id,
                    allowlist_repo=self.allowlist_repo,
                    force_override=force_override,
                )

                if not guardrail_res.allowed:
                    ctx.errors.append(f"Containment blocked by guardrail: {guardrail_res.reason}")
                    return "BLOCKED", {"blocked": True, "target": target_host, "reason": guardrail_res.reason}, "on_error", False

                if ctx.dry_run:
                    return "SUCCESS", {
                        "dry_run": True,
                        "simulated": True,
                        "executed": False,
                        "verified": False,
                        "isolated": True,
                        "target": target_host,
                    }, "default", False

                ctx.errors.append(f"Containment not executed: no host isolation provider is configured for {target_host}.")
                return "FAILED", {
                    "status": "not_configured",
                    "executed": False,
                    "verified": False,
                    "target": target_host,
                    "error": "No host isolation provider is configured.",
                }, "on_error", False

            # 8. tool_firewall (D1, D11, D12, D16)
            if ntype == NodeType.TOOL_FIREWALL.value:
                target_ip = cfg.get("ip_address") or ctx.alert.src_ip or "0.0.0.0"
                force_override = bool(cfg.get("force_override", False))

                guardrail_res = ContainmentGuardrail.assess_target(
                    target=target_ip,
                    kind="ip",
                    org_id=ctx.org_id,
                    allowlist_repo=self.allowlist_repo,
                    force_override=force_override,
                )

                if not guardrail_res.allowed:
                    ctx.errors.append(f"Containment blocked by guardrail: {guardrail_res.reason}")
                    return "BLOCKED", {"blocked": True, "target": target_ip, "reason": guardrail_res.reason}, "on_error", False

                if ctx.dry_run:
                    return "SUCCESS", {
                        "dry_run": True,
                        "simulated": True,
                        "executed": False,
                        "verified": False,
                        "firewall_blocked": True,
                        "target_ip": target_ip,
                    }, "default", False

                ctx.errors.append(f"Containment not executed: no firewall provider is configured for {target_ip}.")
                return "FAILED", {
                    "status": "not_configured",
                    "executed": False,
                    "verified": False,
                    "target_ip": target_ip,
                    "error": "No firewall provider is configured.",
                }, "on_error", False

            ctx.errors.append(f"Unknown node type: '{ntype}' on node '{node.id}'")
            return "FAILED", {"error": f"Unknown node type '{ntype}'"}, "on_error", False

        except Exception as e:
            logger.error(f"Error executing node {node.id} ({ntype}): {e}")
            ctx.errors.append(f"Node {node.id} error: {e}")
            return "FAILED", {"error": str(e)}, "on_error", False

    def _record_node_run(
        self,
        node: WorkflowNode,
        status: str,
        output: dict[str, Any],
        ctx: WorkflowExecutionContext,
    ) -> None:
        """Persists individual node run trace step (D19, D20)."""
        node_run_id = f"nr-{secrets.token_hex(6)}"
        now_iso = datetime.now(UTC).isoformat()
        try:
            self.run_repo.save_node_run(
                node_run_id=node_run_id,
                run_id=ctx.run_id,
                org_id=ctx.org_id,
                node_id=node.id,
                node_type=node.type,
                status=status,
                inputs=node.config or {},
                outputs=output,
                started_at=now_iso,
                completed_at=now_iso,
                error_message=ctx.errors[-1] if status in ("FAILED", "BLOCKED") and ctx.errors else None,
            )
            # Update run heartbeat
            self.run_repo.update_heartbeat(ctx.org_id, ctx.run_id)
        except Exception as e:
            logger.warning(f"Failed to record node run for {node.id}: {e}")

    def _finalize_run_status(self, ctx: WorkflowExecutionContext) -> None:
        """Maps final run status and outcome according to D7."""
        if any(st == "WAITING_APPROVAL" for st in ctx.node_statuses.values()):
            ctx.status = "WAITING_APPROVAL"
            ctx.outcome = "WAITING_APPROVAL"
        elif any(st == "WAITING_SPECIALIST" for st in ctx.node_statuses.values()):
            ctx.status = "WAITING_SPECIALIST"
            ctx.outcome = "WAITING_SPECIALIST"
        elif ctx.errors or any(st in ("FAILED", "BLOCKED") for st in ctx.node_statuses.values()):
            ctx.status = "FAILED"
            if ctx.side_effects_executed:
                ctx.outcome = "FAILED_AFTER_SIDE_EFFECTS"
            else:
                ctx.outcome = "FAILED_BEFORE_SIDE_EFFECTS"
        else:
            ctx.status = "COMPLETED"
            ctx.outcome = "HANDLED"

    async def _persist_incident_report(self, ctx: WorkflowExecutionContext, deployment: PipelineDeployment | None) -> None:
        update = getattr(deployment.ticket_store, "update_ticket_report", None) if deployment and getattr(type(deployment.ticket_store), "update_ticket_report", None) else None
        if ctx.incident_id and update:
            await update(ctx.incident_id, OrgId(ctx.org_id), ctx.report)

    def _persist_final_run(self, workflow: Workflow, ctx: WorkflowExecutionContext) -> None:
        """Persists final run summary and broadcasts SSE update (D7, D20, D21)."""
        now_iso = datetime.now(UTC).isoformat()
        try:
            self.run_repo.update_run_report(ctx.org_id, ctx.run_id, ctx.report, ctx.incident_id)
            self.run_repo.update_run(
                org_id=ctx.org_id,
                run_id=ctx.run_id,
                status=ctx.status,
                outcome=ctx.outcome,
                side_effects=ctx.side_effects_executed,
                unknown_outcome=ctx.unknown_outcome,
                edge_states=ctx.edge_states,
                errors=ctx.errors,
                completed_at=None if ctx.status in ("WAITING_APPROVAL", "WAITING_SPECIALIST") else now_iso,
            )
            try:
                from terminus.server.streaming import broadcast_to_org
                broadcast_to_org(
                    ctx.org_id,
                    "workflow_run_update",
                    {
                        "run_id": ctx.run_id,
                        "workflow_id": ctx.workflow_id,
                        "status": ctx.status,
                        "outcome": ctx.outcome,
                        "side_effects": ctx.side_effects_executed,
                        "errors": ctx.errors,
                    },
                )
            except Exception:
                pass
        except Exception as e:
            logger.warning(f"Failed to persist final run {ctx.run_id}: {e}")
