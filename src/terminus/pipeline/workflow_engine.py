"""Asynchronous DAG Workflow Execution Engine for TERMINUS 2.0.

Executes visual n8n-style node workflows live on incoming alerts and telemetry,
supporting conditional branching, automated tool enrichment, and containment actions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport, SiemAlert, Workflow, WorkflowNode

logger = logging.getLogger("terminus.pipeline.workflow_engine")


@dataclass
class WorkflowExecutionContext:
    workflow_id: str
    org_id: OrgId
    alert: SiemAlert
    report: InvestigationReport | None = None
    node_outputs: dict[str, Any] = field(default_factory=dict)
    executed_nodes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class WorkflowEngine:
    """Evaluates and executes DAG-structured SOC automation workflows."""

    def __init__(self) -> None:
        pass

    async def execute_workflow(
        self,
        workflow: Workflow,
        alert: SiemAlert,
        org_id: OrgId,
        report: InvestigationReport | None = None,
    ) -> WorkflowExecutionContext:
        """Executes a visual node graph for the given alert."""
        ctx = WorkflowExecutionContext(
            workflow_id=workflow.id,
            org_id=org_id,
            alert=alert,
            report=report,
        )

        if not workflow.enabled or not workflow.nodes:
            return ctx

        # Build adjacency graph
        node_map = {n.id: n for n in workflow.nodes}
        out_edges: dict[str, list[str]] = {n.id: [] for n in workflow.nodes}
        in_degrees: dict[str, int] = {n.id: 0 for n in workflow.nodes}

        for edge in workflow.edges:
            if edge.source in out_edges and edge.target in node_map:
                out_edges[edge.source].append(edge.target)
                in_degrees[edge.target] += 1

        # Find entry roots
        queue = [nid for nid, deg in in_degrees.items() if deg == 0]

        while queue:
            current_id = queue.pop(0)
            node = node_map.get(current_id)
            if not node:
                continue

            ctx.executed_nodes.append(current_id)
            should_continue, output = await self._execute_node(node, ctx)
            ctx.node_outputs[current_id] = output

            if should_continue:
                for target_id in out_edges.get(current_id, []):
                    queue.append(target_id)

        return ctx

    async def _execute_node(
        self, node: WorkflowNode, ctx: WorkflowExecutionContext
    ) -> tuple[bool, Any]:
        """Execute a single node by type."""
        ntype = node.type.lower()
        config = node.config or {}

        try:
            # 1. Triggers
            if "trigger" in ntype:
                return True, {"status": "triggered", "alert_id": ctx.alert.id}

            # 2. Condition / Filter Nodes
            if "condition" in ntype or "filter" in ntype:
                min_sev = config.get("min_severity", "high").lower()
                sev_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                if ctx.report:
                    curr_sev = ctx.report.verdict.severity.value.lower()
                    passes = sev_order.get(curr_sev, 1) >= sev_order.get(min_sev, 3)
                    return passes, {"passed": passes, "severity": curr_sev}
                return True, {"passed": True}

            # 3. Notification Nodes
            if "slack" in ntype or "notify" in ntype:
                return True, {"action": "notification_sent", "channel": config.get("channel", "soc-alerts")}

            # 4. Containment Nodes
            if "contain" in ntype or "firewall" in ntype or "response" in ntype:
                target_ip = ctx.alert.src_ip or "none"
                return True, {"action": "containment_proposed", "target_ip": target_ip, "status": "dry_run_connector_not_configured"}

            # Default pass-through
            return True, {"status": "executed", "type": ntype}

        except Exception as e:
            logger.error(f"Error executing workflow node {node.id} ({node.type}): {e}")
            ctx.errors.append(f"Node {node.id}: {e}")
            return False, {"error": str(e)}
