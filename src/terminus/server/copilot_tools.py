"""Comprehensive tenant-scoped Copilot tools for TERMINUS.

Provides incident querying, Agent Fleet configuration, visual DAG workflow building,
containment allowlisting, and dry-run execution testing adhering strictly to Pinned Decisions:
- D1: Exactly 8 node types.
- D11: Strict containment safety gating.
- D12: Copilot never sets force_override (false for new nodes, preserved from stored for existing).
- D13, D22: Copilot-created or structurally-modified workflows default to enabled=false.
- D18: Concurrency/versioning enforcement via expected_version.
- D23: Limits: max 50 nodes, 100 edges, names <= 80 chars, prompt <= 4000 chars, role <= 500 chars.
"""

from __future__ import annotations

import secrets
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from terminus.core.ids import OrgId
from terminus.ingestion.ioc import IocExtractor
from terminus.models import (
    AgentStatus,
    Confidence,
    Evidence,
    InvestigationReport,
    PolicyResult,
    Severity,
    SiemAlert,
    SocAgent,
    Tier,
    Verdict,
    Workflow,
)
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.validation import (
    MAX_EDGES,
    MAX_NAME_LENGTH,
    MAX_NODES,
    validate_workflow,
)
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAgentRepository,
    SqliteAllowlistRepository,
    SqliteWorkflowRepository,
)
from terminus.ticketing.base import TicketStore

# Limits constants (D23)
MAX_ROLE_DESC_LENGTH = 500
MAX_MASTER_PROMPT_LENGTH = 4000

TOOL_SCHEMAS: list[dict[str, Any]] = [
    # ─── Incident Query Tools ───────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "list_incidents",
            "description": "List recent incidents in the current organization with status, severity, host, and source IP.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "Optional status: OPEN, INVESTIGATING, or RESOLVED"}
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_incidents",
            "description": "Search security incidents in the current organization for a specific IP address, hostname, CVE, rule ID, or pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident",
            "description": "Retrieve one incident with its full raw event and forensic assessment by ticket ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ticket_id": {"type": "string", "description": "Exact incident ID"}
                },
                "required": ["ticket_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_platform_knowledge",
            "description": "Retrieve official Terminus platform architectural specifications, triage policies, DAG workflow rules, or containment safety docs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Topic to retrieve: 'overview', 'policies', 'workflows', 'agents', 'containment'",
                    }
                },
                "required": ["topic"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "correlate_sources",
            "description": "Group observed IP addresses across incidents and return supporting incident IDs, hosts, and raw event excerpts.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    # ─── SOC Agent Fleet Tools ──────────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "create_soc_agent",
            "description": "Create a new specialized AI SOC agent in the organization fleet (D23).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Agent name (<= 80 chars)"},
                    "role_description": {"type": "string", "description": "Role description (<= 500 chars)"},
                    "master_prompt": {"type": "string", "description": "Master system prompt (<= 4000 chars)"},
                },
                "required": ["name", "role_description", "master_prompt"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_soc_agent",
            "description": "Update an existing AI SOC agent in the fleet.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Agent ID"},
                    "name": {"type": "string", "description": "Updated name"},
                    "role_description": {"type": "string", "description": "Updated role description"},
                    "master_prompt": {"type": "string", "description": "Updated master prompt"},
                    "status": {"type": "string", "description": "Status: active, paused, maintenance"},
                },
                "required": ["agent_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_soc_agents",
            "description": "List all configured AI SOC agents in the organization.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_soc_agent",
            "description": "Get configuration and status of a specific AI SOC agent.",
            "parameters": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Agent ID"}
                },
                "required": ["agent_id"],
            },
        },
    },
    # ─── Visual DAG Workflow Automation Tools ───────────────────────────
    {
        "type": "function",
        "function": {
            "name": "create_workflow",
            "description": "Create a new visual DAG automation playbook. Playbook is created in disabled draft status (enabled=false, D22). Copilot cannot set force_override (D12).",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Workflow playbook name"},
                    "nodes": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of workflow nodes (exactly 8 types: trigger_wazuh, condition_severity, condition_approval, agent_llm, tool_slack, tool_jira, tool_isolate, tool_firewall)",
                    },
                    "edges": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of directional wires with source, target, and source_handle (default, true, false, on_error)",
                    },
                    "priority": {"type": "integer", "description": "Priority order (lower number = higher priority, default 100)"},
                    "agent_id": {"type": "string", "description": "Optional default SOC agent ID"},
                },
                "required": ["name", "nodes", "edges"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_workflow",
            "description": "Update an existing visual DAG workflow. Requires expected_version (D18). Any structural changes force enabled=false (D13, D22). Preserves existing force_override values (D12).",
            "parameters": {
                "type": "object",
                "properties": {
                    "workflow_id": {"type": "string", "description": "Workflow ID"},
                    "expected_version": {"type": "integer", "description": "Current version of workflow for optimistic concurrency"},
                    "name": {"type": "string", "description": "Workflow name"},
                    "nodes": {"type": "array", "items": {"type": "object"}, "description": "Updated nodes list"},
                    "edges": {"type": "array", "items": {"type": "object"}, "description": "Updated edges list"},
                    "priority": {"type": "integer", "description": "Updated priority"},
                    "agent_id": {"type": "string", "description": "Updated agent ID"},
                },
                "required": ["workflow_id", "expected_version"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_workflow",
            "description": "Get complete definition and node graph of a workflow playbook.",
            "parameters": {
                "type": "object",
                "properties": {
                    "workflow_id": {"type": "string", "description": "Workflow ID"}
                },
                "required": ["workflow_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_workflows",
            "description": "List all visual DAG workflow playbooks in the organization.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "validate_workflow_tool",
            "description": "Validate a workflow DAG structure and containment safety gates before saving.",
            "parameters": {
                "type": "object",
                "properties": {
                    "nodes": {"type": "array", "items": {"type": "object"}},
                    "edges": {"type": "array", "items": {"type": "object"}},
                },
                "required": ["nodes", "edges"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "test_workflow",
            "description": "Run a dry-run test of a workflow with a sample alert without executing side effects or persisting data (D17).",
            "parameters": {
                "type": "object",
                "properties": {
                    "workflow_id": {"type": "string", "description": "Workflow ID to test"},
                    "sample_alert": {"type": "object", "description": "Sample SIEM alert dict"},
                },
                "required": ["workflow_id"],
            },
        },
    },
    # ─── Containment Allowlist Tools ────────────────────────────────────
    {
        "type": "function",
        "function": {
            "name": "list_containment_allowlist",
            "description": "List protected IP addresses and hostnames that cannot be blocked or isolated (D12).",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_containment_allowlist",
            "description": "Add a protected IP or hostname to the safety allowlist.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "Either 'ip' or 'hostname'"},
                    "value": {"type": "string", "description": "Protected IP address or hostname string"},
                    "note": {"type": "string", "description": "Optional description / reason"},
                },
                "required": ["kind", "value"],
            },
        },
    },
]


def compute_full_layout(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Calculates auto-layout coordinates for a DAG of nodes."""
    if not nodes:
        return []

    node_ids = {n["id"] for n in nodes if "id" in n}
    in_degree: dict[str, int] = dict.fromkeys(node_ids, 0)
    adj: dict[str, list[str]] = defaultdict(list)

    for edge in edges:
        src = edge.get("source")
        tgt = edge.get("target")
        if src in node_ids and tgt in node_ids:
            adj[src].append(tgt)
            in_degree[tgt] += 1

    # Topological layering (BFS)
    layers: dict[str, int] = {}
    queue = [nid for nid, deg in in_degree.items() if deg == 0]
    for root in queue:
        layers[root] = 0

    while queue:
        curr = queue.pop(0)
        curr_layer = layers.get(curr, 0)
        for child in adj[curr]:
            if child not in layers or layers[child] < curr_layer + 1:
                layers[child] = curr_layer + 1
                queue.append(child)

    # Group by layer
    layer_groups: dict[int, list[str]] = defaultdict(list)
    for nid in node_ids:
        layer_num = layers.get(nid, 0)
        layer_groups[layer_num].append(nid)

    # Assign x, y
    coords: dict[str, tuple[int, int]] = {}
    for layer_num, nids in sorted(layer_groups.items()):
        for idx, nid in enumerate(nids):
            coords[nid] = (50 + layer_num * 250, 50 + idx * 150)

    result: list[dict[str, Any]] = []
    for n in nodes:
        n_copy = dict(n)
        nid = n_copy.get("id", "")
        if nid in coords:
            n_copy["x"], n_copy["y"] = coords[nid]
        else:
            n_copy["x"] = n_copy.get("x", 0)
            n_copy["y"] = n_copy.get("y", 0)
        result.append(n_copy)

    return result


def place_new_nodes(
    existing_nodes: list[dict[str, Any]],
    new_nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Assigns layout coordinates to newly placed nodes without overlapping existing nodes."""
    max_x = max((n.get("x", 0) for n in existing_nodes), default=0)
    max_y = max((n.get("y", 0) for n in existing_nodes), default=0)

    start_x = max_x + 250 if existing_nodes else 50
    result: list[dict[str, Any]] = []

    for idx, node in enumerate(new_nodes):
        n_copy = dict(node)
        if n_copy.get("x", 0) == 0 and n_copy.get("y", 0) == 0:
            n_copy["x"] = start_x + (idx // 3) * 250
            n_copy["y"] = 50 + (idx % 3) * 150
        result.append(n_copy)

    return result


def _brief_ticket(ticket: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": ticket.get("id"),
        "description": ticket.get("rule_description"),
        "severity": ticket.get("severity"),
        "status": ticket.get("status"),
        "host": ticket.get("agent_name"),
        "source_ip": ticket.get("source_ip"),
        "created_at": ticket.get("created_at"),
        "mitigation_status": ticket.get("mitigation_status"),
        "summary": str(ticket.get("summary") or "")[:300],
    }


class IncidentTools:
    """Multi-domain Copilot tools handler implementing all Terminus capabilities."""

    def __init__(
        self,
        store: TicketStore,
        org_id: OrgId | str,
        db: Database | None = None,
    ) -> None:
        self.store = store
        self.org_id = OrgId(str(org_id))
        self.db = db
        self.agent_repo = SqliteAgentRepository(db=db)
        self.workflow_repo = SqliteWorkflowRepository(db=db)
        self.allowlist_repo = SqliteAllowlistRepository(db=db)
        self.workflow_engine = WorkflowEngine(db=db)

    async def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        org_str = str(self.org_id)

        # ── 1. Incident querying tools ──────────────────────────────────
        if name == "get_incident":
            ticket_id = str(arguments.get("ticket_id") or "")[:100]
            if not ticket_id:
                return {"error": "ticket_id is required"}
            try:
                ticket = await self.store.get_ticket(ticket_id, self.org_id)
            except Exception:
                return {"error": "Incident not found in this organization"}
            return {
                **_brief_ticket(ticket),
                "alert_id": ticket.get("alert_id"),
                "rule_id": ticket.get("rule_id"),
                "mitre": ticket.get("mitre"),
                "full_log": str(ticket.get("full_log") or "")[:3000],
                "policy_reason": ticket.get("policy_reason"),
                "context_notes": ticket.get("context_notes"),
                "threat_intel": ticket.get("threat_intel"),
                "recommended_actions": ticket.get("recommended_actions"),
                "evidence_citations": ticket.get("evidence_citations"),
            }

        if name == "list_incidents":
            tickets = await self.store.list_tickets(self.org_id)
            ordered = sorted(tickets, key=lambda item: str(item.get("created_at") or ""), reverse=True)
            status = str(arguments.get("status") or "").upper()
            if status:
                ordered = [item for item in ordered if str(item.get("status") or "").upper() == status]
            return {"total": len(ordered), "incidents": [_brief_ticket(item) for item in ordered[:30]], "truncated": len(ordered) > 30}

        if name == "search_incidents":
            query = str(arguments.get("query") or "").strip()[:120]
            if not query:
                return {"error": "query is required"}
            tickets = await self.store.list_tickets(self.org_id)
            ordered = sorted(tickets, key=lambda item: str(item.get("created_at") or ""), reverse=True)
            matching = [
                item for item in ordered
                if query.casefold() in " ".join(
                    str(item.get(field) or "")
                    for field in ("id", "alert_id", "rule_description", "agent_name", "source_ip", "summary", "full_log")
                ).casefold()
            ]
            return {
                "query": query,
                "total": len(matching),
                "incidents": [{**_brief_ticket(item), "raw_event_excerpt": str(item.get("full_log") or "")[:700]} for item in matching[:20]],
                "truncated": len(matching) > 20,
            }

        if name == "get_platform_knowledge":
            topic = str(arguments.get("topic") or "overview").lower()
            knowledge_base = {
                "overview": "Terminus is an enterprise multi-tenant AI Security Operations Center (SOC) platform.",
                "policies": "Deterministic Policy Triage Engine evaluates incoming alerts into IGNORE, TRIAGE, ESCALATE.",
                "workflows": "Visual DAG Workflows connect exactly 8 node types to automate SOC response playbooks.",
                "agents": "Specialized AI SOC agent personas for triage, forensics, and active containment.",
                "containment": "Active response with border firewall IP drops and workstation isolation protected by safety gates.",
            }
            return {"topic": topic, "platform": "TERMINUS AI SOC", "content": knowledge_base.get(topic, knowledge_base["overview"])}

        if name == "correlate_sources":
            tickets = await self.store.list_tickets(self.org_id)
            sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for item in tickets[:200]:
                observed = {str(item["source_ip"])} if item.get("source_ip") else set(IocExtractor.extract(str(item.get("full_log") or "")).ipv4s)
                for ip in observed:
                    sources[ip].append({"incident_id": item.get("id"), "host": item.get("agent_name"), "severity": item.get("severity")})
            ranked = sorted(sources.items(), key=lambda pair: (-len(pair[1]), pair[0]))
            return {"observed_sources": [{"ip": ip, "incident_count": len(items)} for ip, items in ranked[:20]]}

        # ── 2. SOC Agent Fleet tools ────────────────────────────────────
        if name == "create_soc_agent":
            agent_name = str(arguments.get("name") or "").strip()
            role_desc = str(arguments.get("role_description") or "").strip()
            master_prompt = str(arguments.get("master_prompt") or "").strip()

            if not agent_name or len(agent_name) > MAX_NAME_LENGTH:
                return {"error": f"Agent name is required and must be <= {MAX_NAME_LENGTH} characters."}
            if len(role_desc) > MAX_ROLE_DESC_LENGTH:
                return {"error": f"Role description must be <= {MAX_ROLE_DESC_LENGTH} characters."}
            if len(master_prompt) > MAX_MASTER_PROMPT_LENGTH:
                return {"error": f"Master prompt must be <= {MAX_MASTER_PROMPT_LENGTH} characters."}

            agent_id = f"agent-{secrets.token_hex(4)}"
            agent = SocAgent(
                id=agent_id,
                name=agent_name,
                role_description=role_desc,
                master_prompt=master_prompt,
                status=AgentStatus.ACTIVE,
                created_at=datetime.now(UTC).isoformat(),
            )
            saved = self.agent_repo.save(agent, org_str)
            return {"success": True, "agent": saved.model_dump()}

        if name == "update_soc_agent":
            agent_id = str(arguments.get("agent_id") or "")
            existing = self.agent_repo.get(agent_id, org_str)
            if not existing:
                return {"error": f"Agent '{agent_id}' not found"}

            new_name = arguments.get("name", existing.name)
            new_role = arguments.get("role_description", existing.role_description)
            new_prompt = arguments.get("master_prompt", existing.master_prompt)
            new_status = arguments.get("status", existing.status)

            if len(new_name) > MAX_NAME_LENGTH:
                return {"error": f"Agent name must be <= {MAX_NAME_LENGTH} characters."}
            if len(new_role) > MAX_ROLE_DESC_LENGTH:
                return {"error": f"Role description must be <= {MAX_ROLE_DESC_LENGTH} characters."}
            if len(new_prompt) > MAX_MASTER_PROMPT_LENGTH:
                return {"error": f"Master prompt must be <= {MAX_MASTER_PROMPT_LENGTH} characters."}

            updated = SocAgent(
                id=existing.id,
                name=new_name,
                role_description=new_role,
                master_prompt=new_prompt,
                status=AgentStatus(new_status) if isinstance(new_status, str) else new_status,
                incidents_processed=existing.incidents_processed,
                avg_sla_ms=existing.avg_sla_ms,
                created_at=existing.created_at,
            )
            saved = self.agent_repo.save(updated, org_str)
            return {"success": True, "agent": saved.model_dump()}

        if name == "list_soc_agents":
            agents = self.agent_repo.list_for_org(org_str)
            return {"agents": [a.model_dump() for a in agents]}

        if name == "get_soc_agent":
            agent_id = str(arguments.get("agent_id") or "")
            agent = self.agent_repo.get(agent_id, org_str)
            if not agent:
                return {"error": f"Agent '{agent_id}' not found"}
            return {"agent": agent.model_dump()}

        # ── 3. Visual DAG Workflow Tools ────────────────────────────────
        if name == "create_workflow":
            wf_name = str(arguments.get("name") or "").strip()
            raw_nodes = arguments.get("nodes", [])
            raw_edges = arguments.get("edges", [])
            priority = int(arguments.get("priority", 100))
            agent_id = arguments.get("agent_id")

            # Check limits (D23)
            if not wf_name or len(wf_name) > MAX_NAME_LENGTH:
                return {"error": f"Workflow name is required and must be <= {MAX_NAME_LENGTH} characters."}
            if len(raw_nodes) > MAX_NODES:
                return {"error": f"Maximum allowed nodes is {MAX_NODES}."}
            if len(raw_edges) > MAX_EDGES:
                return {"error": f"Maximum allowed edges is {MAX_EDGES}."}

            # Enforce D12: Copilot never sets force_override (always false for new nodes)
            sanitized_nodes = []
            override_discarded = False
            for n in raw_nodes:
                n_dict = dict(n)
                ntype = n_dict.get("type", "")
                cfg = dict(n_dict.get("config", {}))
                if ntype in ("tool_isolate", "tool_firewall"):
                    if cfg.get("force_override") is True:
                        override_discarded = True
                    cfg["force_override"] = False
                elif "force_override" in cfg:
                    del cfg["force_override"]
                n_dict["config"] = cfg
                sanitized_nodes.append(n_dict)

            # Compute auto-layout if needed
            if any(n.get("x", 0) == 0 and n.get("y", 0) == 0 for n in sanitized_nodes):
                sanitized_nodes = compute_full_layout(sanitized_nodes, raw_edges)

            wf_id = f"wf-{secrets.token_hex(4)}"
            wf_dict = {
                "id": wf_id,
                "org_id": org_str,
                "name": wf_name,
                "agent_id": agent_id,
                "enabled": False,  # Draft default (D22)
                "priority": priority,
                "version": 1,
                "nodes": sanitized_nodes,
                "edges": raw_edges,
            }

            # Validate workflow (D1, D8, D11, D13)
            val_errors = validate_workflow(wf_dict, caller_role="admin", is_enabling=False)
            if val_errors:
                return {"success": False, "errors": val_errors}

            wf = Workflow.model_validate(wf_dict)
            saved = self.workflow_repo.save_workflow(org_str, wf)

            res: dict[str, Any] = {
                "success": True,
                "workflow": saved.model_dump(),
                "note": "Workflow created in disabled draft mode (enabled=false).",
            }
            if override_discarded:
                res["override_note"] = "force_override is restricted to administrators and was discarded (D12)."
            return res

        if name == "update_workflow":
            wf_id = str(arguments.get("workflow_id") or "")
            expected_version = arguments.get("expected_version")
            if expected_version is None:
                return {"error": "expected_version is required for optimistic concurrency control (D18)."}

            existing = self.workflow_repo.get(wf_id, org_str)
            if not existing:
                return {"error": f"Workflow '{wf_id}' not found"}

            if existing.version != int(expected_version):
                return {
                    "error": f"Version conflict: expected version {expected_version} but current version is {existing.version} (D18)."
                }

            new_name = arguments.get("name", existing.name)
            raw_nodes = arguments.get("nodes")
            raw_edges = arguments.get("edges")
            new_priority = arguments.get("priority", existing.priority)
            new_agent_id = arguments.get("agent_id", existing.agent_id)

            structure_changed = (raw_nodes is not None) or (raw_edges is not None) or (new_agent_id != existing.agent_id)

            # Determine nodes and enforce D12 (copy force_override from existing node if same id, else false)
            override_discarded = False
            if raw_nodes is not None:
                existing_node_map = {n.id: n for n in existing.nodes}
                sanitized_nodes = []
                for n in raw_nodes:
                    n_dict = dict(n)
                    nid = n_dict.get("id")
                    ntype = n_dict.get("type", "")
                    cfg = dict(n_dict.get("config", {}))
                    if ntype in ("tool_isolate", "tool_firewall"):
                        if nid in existing_node_map:
                            stored_override = bool(existing_node_map[nid].config.get("force_override", False))
                            if cfg.get("force_override") is True and not stored_override:
                                override_discarded = True
                            cfg["force_override"] = stored_override
                        else:
                            if cfg.get("force_override") is True:
                                override_discarded = True
                            cfg["force_override"] = False
                    elif "force_override" in cfg:
                        del cfg["force_override"]
                    n_dict["config"] = cfg
                    sanitized_nodes.append(n_dict)

                # Layout any newly added nodes
                existing_node_dicts = [n.model_dump() for n in existing.nodes]
                new_node_dicts = [n for n in sanitized_nodes if n.get("id") not in existing_node_map]
                placed_new = place_new_nodes(existing_node_dicts, new_node_dicts, raw_edges or [e.model_dump() for e in existing.edges])
                placed_map = {n["id"]: n for n in placed_new}
                for idx, n in enumerate(sanitized_nodes):
                    if n.get("id") in placed_map:
                        sanitized_nodes[idx] = placed_map[n["id"]]
            else:
                sanitized_nodes = [n.model_dump() for n in existing.nodes]

            final_edges = raw_edges if raw_edges is not None else [e.model_dump() for e in existing.edges]

            # Structural changes force enabled=False (D13, D22)
            final_enabled = existing.enabled
            if structure_changed:
                final_enabled = False

            updated_dict = {
                "id": existing.id,
                "org_id": org_str,
                "name": new_name,
                "agent_id": new_agent_id,
                "enabled": final_enabled,
                "priority": int(new_priority),
                "version": existing.version + 1,
                "nodes": sanitized_nodes,
                "edges": final_edges,
            }

            val_errors = validate_workflow(updated_dict, caller_role="admin", is_enabling=False)
            if val_errors:
                return {"success": False, "errors": val_errors}

            wf = Workflow.model_validate(updated_dict)
            saved = self.workflow_repo.save_workflow(org_str, wf, expected_version=existing.version)

            res = {
                "success": True,
                "workflow": saved.model_dump(),
            }
            if structure_changed and existing.enabled:
                res["status_note"] = "Structural changes forced workflow to draft mode (enabled=false) (D13, D22)."
            if override_discarded:
                res["override_note"] = "force_override changes from Copilot were discarded (D12)."
            return res

        if name == "get_workflow":
            wf_id = str(arguments.get("workflow_id") or "")
            wf = self.workflow_repo.get(wf_id, org_str)
            if not wf:
                return {"error": f"Workflow '{wf_id}' not found"}
            return {"workflow": wf.model_dump()}

        if name == "list_workflows":
            workflows = self.workflow_repo.list_for_org(org_str)
            return {"workflows": [w.model_dump() for w in workflows]}

        if name == "validate_workflow_tool":
            raw_nodes = arguments.get("nodes", [])
            raw_edges = arguments.get("edges", [])
            temp_dict = {
                "id": "wf-validate-temp",
                "org_id": org_str,
                "name": "Validation Target",
                "enabled": False,
                "priority": 100,
                "version": 1,
                "nodes": raw_nodes,
                "edges": raw_edges,
            }
            val_errors = validate_workflow(temp_dict, caller_role="admin", is_enabling=False)
            return {"valid": len(val_errors) == 0, "errors": val_errors}

        if name == "test_workflow":
            wf_id = str(arguments.get("workflow_id") or "")
            wf = self.workflow_repo.get(wf_id, org_str)
            if not wf:
                return {"error": f"Workflow '{wf_id}' not found"}

            sample_alert_dict = arguments.get("sample_alert") or {
                "id": "alt-test-sample",
                "rule_id": "5710",
                "level": 12,
                "description": "Test alert for workflow execution",
                "src_ip": "198.51.100.42",
            }
            sample_alert = SiemAlert.model_validate(sample_alert_dict)

            # Create deterministic stub report
            sample_report = InvestigationReport(
                alert_id=sample_alert.id,
                policy=PolicyResult(alert_id=sample_alert.id, tier=Tier.ESCALATE, should_investigate=True, reason="Test dry-run"),
                verdict=Verdict(severity=Severity.HIGH, confidence=Confidence.HIGH, summary="Sample dry-run report", recommended_actions=[]),
                evidence=Evidence(alert=sample_alert, agent_name="agent-triage", threat_intel="Sample intel", context_notes="Dry-run context"),
            )

            # Dry run execution (D17)
            ctx = await self.workflow_engine.execute_workflow(
                workflow=wf,
                alert=sample_alert,
                base_report=sample_report,
                org_id=org_str,
                deployment=PipelineDeployment(
                    policy_engine=None,  # type: ignore
                    agent=None,  # type: ignore
                    notifier=None,  # type: ignore
                    ticket_store=self.store,
                ),
                dry_run=True,
            )

            return {
                "dry_run": True,
                "status": ctx.status,
                "outcome": ctx.outcome,
                "executed_nodes": ctx.executed_nodes,
                "node_statuses": ctx.node_statuses,
                "edge_states": ctx.edge_states,
                "errors": ctx.errors,
            }

        # ── 4. Containment Allowlist Tools ──────────────────────────────
        if name == "list_containment_allowlist":
            entries = self.allowlist_repo.list_entries(org_str)
            return {"allowlist": entries}

        if name == "add_containment_allowlist":
            kind = str(arguments.get("kind") or "ip").lower()
            value = str(arguments.get("value") or "").strip()
            note = arguments.get("note")

            if not value:
                return {"error": "value is required"}
            if kind not in ("ip", "hostname"):
                return {"error": "kind must be 'ip' or 'hostname'"}

            entry_id = f"al-{secrets.token_hex(4)}"
            entry = self.allowlist_repo.add_entry(
                entry_id=entry_id,
                org_id=org_str,
                kind=kind,
                value=value,
                note=note,
                created_by="copilot",
            )
            return {"success": True, "entry": entry}

        return {"error": f"Unknown tool '{name}'"}
