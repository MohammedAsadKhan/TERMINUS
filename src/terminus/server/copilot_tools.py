"""Read-only, tenant-scoped incident tools exposed to the analyst copilot."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from terminus.core.ids import OrgId
from terminus.ingestion.ioc import IocExtractor
from terminus.ticketing.base import TicketStore


TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_incidents",
            "description": "List recent incidents in the current organization with status, severity, host, and source IP. Use to understand the queue before answering broad questions.",
            "parameters": {"type": "object", "properties": {"status": {"type": "string", "description": "Optional status: OPEN, INVESTIGATING, or RESOLVED"}}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_incidents",
            "description": "Search live security incident records in the current organization for a specific IP address, hostname, CVE, rule ID, or payload pattern. Do NOT use this tool for questions about Terminus platform capabilities, features, or architecture.",
            "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "Specific IP address, hostname, CVE, rule ID, or indicator to find in recorded incidents"}}, "required": ["query"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_incident",
            "description": "Retrieve one incident with its full raw event and assessment. Use its exact ID from list_incidents or search_incidents.",
            "parameters": {"type": "object", "properties": {"ticket_id": {"type": "string", "description": "Exact incident ID"}}, "required": ["ticket_id"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_platform_knowledge",
            "description": "Retrieve official Terminus platform architectural specifications, deterministic policy triage rules, DAG workflow automation procedures, agent fleet configuration, attack graph topology design, or SOAR containment capabilities.",
            "parameters": {
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Topic to retrieve: 'overview', 'policies', 'workflows', 'agents', 'topology_graph', 'containment', 'licensing', 'reporting'",
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
            "description": "Group observed IP addresses across incidents and return supporting incident IDs, hosts, and raw event excerpts. Observed IPs are leads, not confirmed attackers.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


def _brief(ticket: dict[str, Any]) -> dict[str, Any]:
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
    def __init__(self, store: TicketStore, org_id: OrgId) -> None:
        self.store = store
        self.org_id = org_id

    async def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "get_incident":
            ticket_id = str(arguments.get("ticket_id") or "")[:100]
            if not ticket_id:
                return {"error": "ticket_id is required"}
            try:
                ticket = await self.store.get_ticket(ticket_id, self.org_id)
            except Exception:
                return {"error": "Incident not found in this organization"}
            return {
                **_brief(ticket),
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

        tickets = await self.store.list_tickets(self.org_id)
        ordered = sorted(tickets, key=lambda item: str(item.get("created_at") or ""), reverse=True)

        if name == "list_incidents":
            status = str(arguments.get("status") or "").upper()
            if status:
                ordered = [item for item in ordered if str(item.get("status") or "").upper() == status]
            return {"total": len(ordered), "incidents": [_brief(item) for item in ordered[:30]], "truncated": len(ordered) > 30}

        if name == "search_incidents":
            query = str(arguments.get("query") or "").strip()[:120]
            if not query:
                return {"error": "query is required"}
            matching = [item for item in ordered if query.casefold() in " ".join(str(item.get(field) or "") for field in ("id", "alert_id", "rule_description", "agent_name", "source_ip", "summary", "full_log")).casefold()]
            return {"query": query, "total": len(matching), "incidents": [{**_brief(item), "raw_event_excerpt": str(item.get("full_log") or "")[:700]} for item in matching[:20]], "truncated": len(matching) > 20}

        if name == "get_platform_knowledge":
            topic = str(arguments.get("topic") or "overview").lower()
            knowledge_base = {
                "overview": (
                    "Terminus is an enterprise commercial AI Security Operations Center (SOC) platform built on top of Wazuh SIEM. "
                    "It pairs sub-millisecond deterministic policy triage with autonomous AI investigation agents, "
                    "a 7-day attack relationship topology canvas, visual DAG workflow automation, and multi-tenant SaaS RBAC."
                ),
                "policies": (
                    "The Deterministic Policy Triage Engine processes all incoming security alerts before calling LLMs using deterministic rules: "
                    "1. IGNORE (Alert Level < 5): Low-priority noise is suppressed with zero LLM token cost. "
                    "2. TRIAGE (Alert Level 5–9): Evaluated by autonomous AI investigation agents and recorded as an incident ticket. "
                    "3. ESCALATE (Alert Level >= 10 or recognized MITRE ATT&CK technique): Immediate high-priority incident triggering automated containment workflows."
                ),
                "workflows": (
                    "Visual DAG Workflows allow security engineers to design visual trigger-condition-action automation pipelines in the console: "
                    "• Triggers: Wazuh alert webhook ingestion, Cron schedules. "
                    "• Conditions: Severity thresholds, MITRE filters. "
                    "• Investigation: Routing to custom agent personas. "
                    "• Containment & Outputs: Slack channel alerts, Jira ticket creation, firewall boundary blocks, host network isolation."
                ),
                "agents": (
                    "Agent Fleet allows administrators to define specialized autonomous SOC subagents with tailored role descriptions, "
                    "system prompts, and operational statuses (active, paused, maintenance) for multi-stage forensics."
                ),
                "topology_graph": (
                    "The Attack Relationship Topology Canvas is an interactive 7-day visualization correlating adversary source IPs, victim hosts, "
                    "and MITRE ATT&CK techniques across all observed telemetry with cross-filtering to the incident queue."
                ),
                "containment": (
                    "SOAR Active Containment executes multi-domain response actions (boundary firewall drop, host network isolation, IAM credential revocation) "
                    "protected by deterministic blast-radius guardrails on critical infrastructure."
                ),
                "reporting": (
                    "Executive Operations Summaries generate immutable 24-hour and custom observation window snapshots "
                    "with severity distributions, top impacted hosts, and exportable JSON audit records."
                ),
            }
            content = knowledge_base.get(topic) or knowledge_base.get("overview")
            return {"topic": topic, "platform": "TERMINUS AI SOC", "content": content}

        if name == "correlate_sources":
            sources: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for item in ordered[:200]:
                # Structured source IP takes precedence. Raw logs may also contain
                # destination or internal addresses that are not attack sources.
                observed = {str(item["source_ip"])} if item.get("source_ip") else set(IocExtractor.extract(str(item.get("full_log") or "")).ipv4s)
                for ip in observed:
                    sources[ip].append({"incident_id": item.get("id"), "host": item.get("agent_name"), "severity": item.get("severity"), "event_excerpt": str(item.get("full_log") or "")[:300]})
            ranked = sorted(sources.items(), key=lambda pair: (-len(pair[1]), pair[0]))
            return {"observed_sources": [{"ip": ip, "incident_count": len(items), "evidence": items[:8]} for ip, items in ranked[:20]], "note": "An observed IP is a lead, not proof of attacker identity."}

        return {"error": "Unknown tool"}
