"""Workflow DAG Validation and Policy Gate Enforcement for TERMINUS.

Implements all static workflow checks (D1, D8, D11, D13, D23):
1. Node registry validation (exactly 8 types)
2. Schema & extra="forbid" config validation
3. Edge handle rules (true/false/on_error vs default/on_error)
4. DAG cycle detection (no loops)
5. Containment safety gating (D11: all paths to containment must pass through
   condition_approval or condition_severity with min_level > 0 on 'true' handle)
6. Administrative role requirements (D13)
7. Size limits (50 nodes, 100 edges, 80-char names)
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from terminus.models import Workflow, WorkflowEdge, WorkflowNode
from terminus.pipeline.nodes.schemas import (
    TYPE_TO_SCHEMA,
    VALID_OUTPUT_HANDLES,
    ConditionSeverityConfig,
    NodeType,
)

MAX_NODES = 50
MAX_EDGES = 100
MAX_NAME_LENGTH = 80

CONTAINMENT_NODE_TYPES = {NodeType.TOOL_ISOLATE.value, NodeType.TOOL_FIREWALL.value}
APPROVAL_NODE_TYPES = {NodeType.CONDITION_APPROVAL.value}


def validate_workflow(
    workflow: Workflow | dict[str, Any],
    caller_role: str = "admin",
    is_enabling: bool = False,
) -> list[str]:
    """Validates workflow definition and containment safety gates.

    Returns a list of validation error descriptions. An empty list indicates
    a fully valid workflow.
    """
    errors: list[str] = []

    # 1. Parse workflow object
    if isinstance(workflow, dict):
        try:
            wf = Workflow.model_validate(workflow)
        except ValidationError as e:
            return [f"Workflow schema error: {e}"]
    else:
        wf = workflow

    # 2. Limits checks (D23)
    if not wf.name or not wf.name.strip() or len(wf.name) > MAX_NAME_LENGTH:
        errors.append(f"A workflow name is required and must be between 1 and {MAX_NAME_LENGTH} characters.")

    if len(wf.nodes) > MAX_NODES:
        errors.append(f"Workflow exceeds maximum allowed nodes ({len(wf.nodes)} > {MAX_NODES}).")

    if len(wf.edges) > MAX_EDGES:
        errors.append(f"Workflow exceeds maximum allowed edges ({len(wf.edges)} > {MAX_EDGES}).")

    # 3. Node checks (D1)
    node_map: dict[str, WorkflowNode] = {}
    has_containment = False
    has_approval = False

    for node in wf.nodes:
        if node.id in node_map:
            errors.append(f"Node IDs must be unique: '{node.id}' is duplicated.")
        node_map[node.id] = node

        if node.type not in TYPE_TO_SCHEMA:
            errors.append(f"Unknown node type: '{node.type}' on node '{node.id}'.")
            continue

        if node.type in CONTAINMENT_NODE_TYPES:
            has_containment = True
        if node.type in APPROVAL_NODE_TYPES:
            has_approval = True

        # Validate config with strict schema
        schema_cls = TYPE_TO_SCHEMA[node.type]
        try:
            schema_cls.model_validate(node.config or {})
        except ValidationError as e:
            errors.append(f"Invalid config for node '{node.id}' ({node.type}): {e}")

    # 4. Role check for enabling containment/approval workflows (D13)
    if (is_enabling or wf.enabled) and (has_containment or has_approval):
        if caller_role != "admin":
            errors.append("Enabling a workflow containing containment or approval nodes requires 'admin' role.")

    # 5. Edge checks (D8)
    adj: dict[str, list[WorkflowEdge]] = {n.id: [] for n in wf.nodes}
    in_degree: dict[str, int] = {n.id: 0 for n in wf.nodes}

    for edge in wf.edges:
        if edge.source not in node_map:
            errors.append(f"Every edge must connect existing nodes: non-existent source node '{edge.source}'.")
            continue
        if edge.target not in node_map:
            errors.append(f"Every edge must connect existing nodes: non-existent target node '{edge.target}'.")
            continue

        src_node = node_map[edge.source]
        valid_handles = VALID_OUTPUT_HANDLES.get(src_node.type, {"default", "on_error"})
        handle = edge.source_handle or "default"
        if handle not in valid_handles:
            errors.append(
                f"Invalid source_handle '{handle}' for node '{src_node.id}' of type '{src_node.type}'. "
                f"Allowed: {sorted(valid_handles)}"
            )

        adj[edge.source].append(edge)
        in_degree[edge.target] += 1

    # 6. Cycle detection (DAG check)
    visited: dict[str, int] = {}  # 0: unvisited, 1: visiting, 2: visited

    def has_cycle(node_id: str) -> bool:
        visited[node_id] = 1
        for e in adj.get(node_id, []):
            nxt = e.target
            if visited.get(nxt, 0) == 1:
                return True
            if visited.get(nxt, 0) == 0:
                if has_cycle(nxt):
                    return True
        visited[node_id] = 2
        return False

    for nid in wf.nodes:
        if visited.get(nid.id, 0) == 0:
            if has_cycle(nid.id):
                errors.append("Cycles are not supported; workflow contains a cycle or loop; workflows must be a Directed Acyclic Graph (DAG).")
                break

    # 7. Containment Gate Safety Check (D11)
    # Every path from any root/trigger node to a containment node must pass through either:
    # (a) the 'true' edge of a condition_approval node, OR
    # (b) the 'true' edge of a condition_severity node with min_level > 0.
    if has_containment and not any("cycle" in e.lower() for e in errors):
        containment_nodes = [n for n in wf.nodes if n.type in CONTAINMENT_NODE_TYPES]
        root_nodes = [n for n in wf.nodes if in_degree[n.id] == 0]

        for c_node in containment_nodes:
            # For each containment node, verify all paths from every root to this node are gated
            for r_node in root_nodes:
                ungated_path = _find_ungated_path(
                    current_node_id=r_node.id,
                    target_node_id=c_node.id,
                    node_map=node_map,
                    adj=adj,
                    is_gated=False,
                    visited=set(),
                )
                if ungated_path is not None:
                    path_str = " -> ".join(ungated_path)
                    errors.append(
                        f"Containment node '{c_node.id}' ({c_node.type}) is reachable via ungated path: [{path_str}]. "
                        f"All containment paths must pass through the 'true' edge of a condition_approval or "
                        f"a condition_severity with min_level > 0 (D11)."
                    )
                    break

    return errors


def _find_ungated_path(
    current_node_id: str,
    target_node_id: str,
    node_map: dict[str, WorkflowNode],
    adj: dict[str, list[WorkflowEdge]],
    is_gated: bool,
    visited: set[str],
) -> list[str] | None:
    """DFS to find if there is any path from current_node to target_node where is_gated is False."""
    if current_node_id == target_node_id:
        return [current_node_id] if not is_gated else None

    if current_node_id in visited:
        return None

    visited.add(current_node_id)
    curr_node = node_map.get(current_node_id)

    for edge in adj.get(current_node_id, []):
        nxt_id = edge.target
        nxt_gated = is_gated

        if not is_gated and curr_node:
            handle = edge.source_handle or "default"
            if handle == "true":
                if curr_node.type == NodeType.CONDITION_APPROVAL.value:
                    nxt_gated = True
                elif curr_node.type == NodeType.CONDITION_SEVERITY.value:
                    cfg = curr_node.config or {}
                    try:
                        parsed = ConditionSeverityConfig.model_validate(cfg)
                        if parsed.min_level > 0:
                            nxt_gated = True
                    except Exception:
                        pass

        res = _find_ungated_path(nxt_id, target_node_id, node_map, adj, nxt_gated, visited.copy())
        if res is not None:
            return [current_node_id] + res

    return None
