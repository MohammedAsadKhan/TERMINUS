"""Service Connection Sensor and Dynamic Auto-Configuration Engine for TERMINUS.

Tracks real-time SIEM and telemetry service connections, heartbeats, and auto-provisions
the SOC baseline (allowlists, agent fleet, DAG playbooks) when services connect or disconnect.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from terminus.models import AgentStatus, SocAgent, Workflow, WorkflowEdge, WorkflowNode


def _workflow_seed_signature(workflow: Workflow) -> tuple[Any, ...]:
    """Return persisted workflow fields used to recognize an untouched old seed."""
    return (
        workflow.id,
        workflow.name,
        workflow.agent_id,
        workflow.enabled,
        workflow.priority,
        tuple(tuple(sorted(node.model_dump().items())) for node in workflow.nodes),
        tuple(tuple(sorted(edge.model_dump().items())) for edge in workflow.edges),
    )


def _seed_workflows(now_iso: str) -> tuple[list[Workflow], list[Workflow]]:
    """Build corrected baseline playbooks and exact legacy definitions for safe upgrades."""
    corrected = [
        Workflow(
            id="wf-slack-triage",
            name="High-Severity Slack Notification",
            description="Immediately alerts the on-call security team on Slack when high-severity incidents occur.",
            enabled=True,
            nodes=[
                WorkflowNode(id="n1", type="trigger_wazuh", label="Alert Trigger", config={}, x=0, y=0),
                WorkflowNode(id="n2", type="condition_severity", label="Wazuh level >= 3", config={"min_level": 3}, x=240, y=0),
                WorkflowNode(id="n3", type="tool_slack", label="Post to #soc-alerts", config={"channel": "#soc-alerts"}, x=480, y=0),
            ],
            edges=[
                WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
            ],
            created_at=now_iso,
            updated_at=now_iso,
        ),
        Workflow(
            id="wf-ransomware-containment",
            name="Ransomware Workstation Containment Gated Flow",
            description="Requires mandatory SOC analyst approval before requesting workstation isolation.",
            enabled=True,
            nodes=[
                WorkflowNode(id="n1", type="trigger_wazuh", label="Ransomware Trigger", config={}, x=0, y=0),
                WorkflowNode(id="n2", type="condition_severity", label="Wazuh level >= 4", config={"min_level": 4}, x=240, y=0),
                WorkflowNode(
                    id="n3",
                    type="condition_approval",
                    label="Mandatory Human Approval",
                    config={
                        "required_role": "admin",
                        "prompt_message": "Approve simulated workstation isolation for this ransomware alert.",
                        "timeout_seconds": 300,
                    },
                    x=480,
                    y=0,
                ),
                WorkflowNode(id="n4", type="tool_isolate", label="Simulate Host Isolation", config={}, x=720, y=0),
                WorkflowNode(id="n5", type="tool_slack", label="Report Response Outcome", config={"channel": "#soc-containment"}, x=960, y=0),
            ],
            edges=[
                WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
                WorkflowEdge(id="e3", source="n3", target="n4", source_handle="true"),
                WorkflowEdge(id="e4", source="n4", target="n5", source_handle="default"),
            ],
            created_at=now_iso,
            updated_at=now_iso,
        ),
    ]

    # These match only the two invalid definitions shipped by the previous sensor.
    # Comparing the complete persisted graph prevents replacing analyst edits.
    legacy = [
        Workflow(
            id="wf-slack-triage",
            name="High-Severity Slack Notification",
            enabled=True,
            nodes=[
                WorkflowNode(id="n1", type="trigger_wazuh", label="", config={}, x=0, y=0, name="Alert Trigger"),
                WorkflowNode(id="n2", type="condition_severity", label="", config={"min_level": 3}, x=0, y=0, name="Severity >= HIGH"),
                WorkflowNode(id="n3", type="tool_slack", label="", config={"channel": "#soc-alerts"}, x=0, y=0, name="Post to #soc-alerts"),
            ],
            edges=[
                WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                WorkflowEdge(id="e2", source="n2", target="n3", source_handle="default"),
            ],
        ),
        Workflow(
            id="wf-ransomware-containment",
            name="Ransomware Workstation Containment Gated Flow",
            enabled=True,
            nodes=[
                WorkflowNode(id="n1", type="trigger_wazuh", label="", config={}, x=0, y=0, name="Ransomware Trigger"),
                WorkflowNode(id="n2", type="condition_severity", label="", config={"min_level": 4}, x=0, y=0, name="Severity >= CRITICAL"),
                WorkflowNode(id="n3", type="condition_approval", label="", config={"action_type": "isolate_host", "timeout_seconds": 300}, x=0, y=0, name="Mandatory Human Approval"),
                WorkflowNode(id="n4", type="tool_isolate", label="", config={}, x=0, y=0, name="Execute Host Isolation"),
                WorkflowNode(id="n5", type="tool_slack", label="", config={"channel": "#soc-containment"}, x=0, y=0, name="Broadcast Isolation Confirmed"),
            ],
            edges=[
                WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                WorkflowEdge(id="e2", source="n2", target="n3", source_handle="default"),
                WorkflowEdge(id="e3", source="n3", target="n4", source_handle="default"),
                WorkflowEdge(id="e4", source="n4", target="n5", source_handle="default"),
            ],
        ),
    ]
    return corrected, legacy


class ServiceConnectionSensor:
    """Manages telemetry service connectivity state and dynamic auto-configuration."""

    def __init__(self) -> None:
        self.service_started_at: datetime = datetime.now(UTC)
        self.last_telemetry_at: datetime | None = None
        self.last_heartbeat_at: datetime | None = None
        self.connected_sources: dict[str, dict[str, Any]] = {}
        self.is_streaming: bool = False
        self.total_alerts_ingested: int = 0
        self.total_actions_taken: int = 0
        self.configured_orgs: set[str] = set()

    def record_telemetry_event(self, source: str = "wazuh_webhook", alert_id: str | None = None) -> None:
        """Record an incoming live telemetry alert from a SIEM or simulation source."""
        now = datetime.now(UTC)
        self.last_telemetry_at = now
        self.total_alerts_ingested += 1
        self.connected_sources[source] = {
            "source": source,
            "status": "active",
            "last_seen": now.isoformat(),
            "last_alert_id": alert_id,
        }

    def register_heartbeat(self, source: str, status: str = "connected", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        """Register or update a heartbeat from an external telemetry or simulation service."""
        now = datetime.now(UTC)
        self.last_heartbeat_at = now
        if status == "disconnected":
            if source in self.connected_sources:
                self.connected_sources[source]["status"] = "disconnected"
                self.connected_sources[source]["last_seen"] = now.isoformat()
        else:
            self.connected_sources[source] = {
                "source": source,
                "status": status,
                "last_seen": now.isoformat(),
                "metadata": metadata or {},
            }
        return self.get_status()

    def get_status(self) -> dict[str, Any]:
        """Compute the current real-time service connection status."""
        now = datetime.now(UTC)
        active_sources = [
            s for s, info in self.connected_sources.items()
            if info.get("status") in {"connected", "active"}
            and (now - datetime.fromisoformat(info["last_seen"])).total_seconds() < 45
        ]

        if active_sources:
            overall_status = "STREAMING" if self.last_telemetry_at and (now - self.last_telemetry_at).total_seconds() < 15 else "CONNECTED"
        elif self.last_telemetry_at and (now - self.last_telemetry_at).total_seconds() < 60:
            overall_status = "IDLE"
        else:
            overall_status = "READY"

        uptime_seconds = int((now - self.service_started_at).total_seconds())

        return {
            "status": overall_status,
            "service_mode": "Autonomous SOC / SOAR Standalone Service",
            "uptime_seconds": uptime_seconds,
            "service_started_at": self.service_started_at.isoformat(),
            "last_telemetry_at": self.last_telemetry_at.isoformat() if self.last_telemetry_at else None,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat() if self.last_heartbeat_at else None,
            "connected_sources": self.connected_sources,
            "active_sources_count": len(active_sources),
            "total_alerts_ingested": self.total_alerts_ingested,
            "total_actions_taken": self.total_actions_taken,
        }

    def auto_configure_baseline(self, org_id: str, agent_repo: Any, workflow_repo: Any, allowlist_repo: Any) -> dict[str, Any]:
        """Auto-configure the standard SOC baseline for an organization when detected."""
        now_iso = datetime.now(UTC).isoformat()

        # 1. Standard Agent Fleet Personas
        standard_agents = [
            SocAgent(
                id="agent-triage",
                name="Triage Sentinel",
                role_description="Sub-millisecond alert filtering, MITRE tag correlation, and Tier-0 noise suppression.",
                master_prompt="You are the Triage Sentinel AI Agent. Your primary role is to inspect incoming raw SIEM telemetry from Wazuh, evaluate alert severity levels against organizational policy rules, and filter out low-level operational noise without consuming unnecessary LLM token quota.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=1.2,
                created_at=now_iso,
            ),
            SocAgent(
                id="agent-forensic",
                name="Forensic Investigator",
                role_description="Deep LLM evidence collection, threat intel enrichment, payload breakdown, and root cause reasoning.",
                master_prompt="You are the Forensic Investigator AI Agent. Your role is to perform deep-dive analysis on high-severity security incidents. You gather process execution trees, inspect network payload strings, correlate IOCs against threat intelligence feeds, and render structured JSON verdicts with high-confidence root cause explanations.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=450.0,
                created_at=now_iso,
            ),
            SocAgent(
                id="agent-containment",
                name="Containment Operator",
                role_description="Executes network boundary firewall blocks, host workstation isolations, and service credential revocations.",
                master_prompt="You are the Containment Operator AI Agent. Your role is to execute automated remediation playbooks when critical threats are identified.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=15.0,
                created_at=now_iso,
            ),
        ]

        for agent in standard_agents:
            if not agent_repo.get(agent.id, org_id):
                agent_repo.save(agent, org_id)

        # 2. Standard Baseline DAG Workflows
        standard_workflows, legacy_workflows = _seed_workflows(now_iso)
        legacy_by_id = {wf.id: wf for wf in legacy_workflows}
        for wf in standard_workflows:
            existing = workflow_repo.get(wf.id, org_id)
            if existing is None or _workflow_seed_signature(existing) == _workflow_seed_signature(legacy_by_id[wf.id]):
                workflow_repo.save(wf, org_id)

        # 3. Standard Critical Allowlist Safeguards (D12/D14)
        standard_allowlists = [
            ("host", "dc01.corp.internal", "Domain Controller 01 - Critical Identity Infrastructure"),
            ("host", "dc02.corp.internal", "Domain Controller 02 - Backup Identity Infrastructure"),
            ("subnet", "10.0.0.0/24", "Core Server Management Subnet"),
            ("ip", "10.0.0.1", "Core Gateway Router"),
        ]

        from uuid import uuid4
        for kind, val, note in standard_allowlists:
            if not allowlist_repo.is_allowlisted(org_id, val):
                allowlist_repo.add_entry(f"al-auto-{uuid4().hex[:8]}", org_id, kind, val, note)

        self.configured_orgs.add(org_id)
        return {
            "status": "auto_configured",
            "org_id": org_id,
            "agents_configured": len(standard_agents),
            "workflows_configured": len(standard_workflows),
            "allowlists_configured": len(standard_allowlists),
        }


# Global singleton sensor instance
service_sensor = ServiceConnectionSensor()
