"""Persistence repositories for TERMINUS 2.0.

Provides robust SQLite-backed stores for Incidents, Organizations, Users,
Memberships, SocAgents, Workflows, WorkflowRuns, Approvals, AlertClaims,
Allowlists, and AuditLogs.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import UTC, datetime
from typing import Any

from terminus.auth.models import User
from terminus.core.base import ConflictError, NotFoundError
from terminus.core.ids import OrgId, TicketId, UserId
from terminus.models import (
    AgentStatus,
    InvestigationReport,
    SiemAlert,
    SocAgent,
    Workflow,
    WorkflowEdge,
    WorkflowNode,
)
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.storage.db import Database


class SqliteIncidentRepository:
    """Persistent SQLite-backed ticket and incident store."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    async def create_ticket(
        self,
        report: InvestigationReport,
        org_id: OrgId | str,
        evidence_citations: list[dict[str, Any]] | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> TicketId:
        self._ensure_org(str(org_id))
        ticket_id = TicketId("TICK-" + secrets.token_hex(4).upper())
        alert = report.evidence.alert

        rule_desc = (alert.rule_description or alert.description or "").lower()
        if "lsass" in rule_desc or "credential" in rule_desc or "kerberos" in rule_desc:
            kill_chain_stage = "Credential Access"
        elif "log4j" in rule_desc or "exploit" in rule_desc or "webhook" in rule_desc:
            kill_chain_stage = "Initial Access"
        elif "root" in rule_desc or "privilege" in rule_desc or "bypass" in rule_desc:
            kill_chain_stage = "Privilege Escalation"
        elif "ransomware" in rule_desc or "exfil" in rule_desc or "honeypot" in rule_desc or "canary" in rule_desc:
            kill_chain_stage = "Exfiltration & Impact"
        else:
            kill_chain_stage = "Execution"

        now_iso = alert.timestamp or datetime.now(UTC).isoformat()
        rec_actions_str = json.dumps(report.verdict.recommended_actions)
        citations_str = json.dumps(evidence_citations or [])
        payload_str = json.dumps(raw_payload or alert.model_dump())

        sql = """
        INSERT INTO incidents (
            ticket_id, org_id, alert_id, rule_id, rule_description,
            severity, confidence, summary, recommended_actions,
            agent_name, threat_intel, context_notes, full_log,
            policy_tier, policy_reason, status, asset_criticality,
            kill_chain_stage, threat_intel_score, time_to_decision_sec,
            mitigation_status, evidence_citations_json, raw_payload_json,
            created_at, updated_at, resolved_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """
        params = (
            str(ticket_id),
            str(org_id),
            alert.id,
            str(alert.rule_id),
            alert.rule_description or alert.description,
            report.verdict.severity.value,
            report.verdict.confidence.value,
            report.verdict.summary,
            rec_actions_str,
            report.evidence.agent_name or alert.agent_name or "Unknown host",
            report.evidence.threat_intel,
            report.evidence.context_notes,
            alert.full_log or "",
            report.policy.tier.value,
            report.policy.reason,
            "OPEN",
            "MEDIUM",
            kill_chain_stage,
            "Verified",
            0.42,
            "NOT_EXECUTED",
            citations_str,
            payload_str,
            now_iso,
            now_iso,
            "",
        )
        self.db.execute(sql, params)
        return ticket_id

    async def get_ticket(self, ticket_id: TicketId | str, org_id: OrgId | str) -> dict[str, Any]:
        sql = "SELECT * FROM incidents WHERE ticket_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (str(ticket_id), str(org_id)))
        if not row:
            raise NotFoundError(f"Ticket {ticket_id} not found for org {org_id}")
        return self._format_ticket(row)

    async def list_tickets(
        self,
        org_id: OrgId | str,
        limit: int = 100,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM incidents WHERE org_id = ?"
        params: list[Any] = [str(org_id)]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(sql, tuple(params))
        return [self._format_ticket(r) for r in rows]

    async def update_ticket_status(
        self,
        ticket_id: TicketId | str,
        org_id: OrgId | str,
        new_status: str,
        mitigation_status: str | None = None,
    ) -> dict[str, Any]:
        now_iso = datetime.now(UTC).isoformat()
        resolved_at = now_iso if new_status in ("RESOLVED", "CLOSED", "FALSE_POSITIVE") else ""
        sql = """
        UPDATE incidents
        SET status = ?, updated_at = ?, resolved_at = COALESCE(NULLIF(?, ''), resolved_at)
        """
        params: list[Any] = [new_status, now_iso, resolved_at]
        if mitigation_status is not None:
            sql += ", mitigation_status = ?"
            params.append(mitigation_status)
        sql += " WHERE ticket_id = ? AND org_id = ?"
        params.extend([str(ticket_id), str(org_id)])
        self.db.execute(sql, tuple(params))
        return await self.get_ticket(ticket_id, org_id)

    def _format_ticket(self, row: dict[str, Any]) -> dict[str, Any]:
        res = dict(row)
        res["id"] = res["ticket_id"]
        try:
            res["recommended_actions"] = json.loads(res.get("recommended_actions") or "[]")
        except Exception:
            res["recommended_actions"] = []
        try:
            res["evidence_citations"] = json.loads(res.get("evidence_citations_json") or "[]")
        except Exception:
            res["evidence_citations"] = []
        try:
            res["raw_payload"] = json.loads(res.get("raw_payload_json") or "{}")
        except Exception:
            res["raw_payload"] = {}
        return res


class SqliteOrgRepository:
    """Persistent SQLite-backed organization store."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def create(self, org: Organization, org_id: OrgId) -> Organization:
        sql = """
        INSERT INTO organizations (org_id, name, created_at, license_ref, settings_json)
        VALUES (?, ?, ?, ?, ?)
        """
        created_str = org.created_at.isoformat() if hasattr(org.created_at, "isoformat") else str(org.created_at)
        self.db.execute(sql, (str(org_id), org.name, created_str, org.license_ref, "{}"))
        return org

    def get(self, org_id: OrgId, caller_org: OrgId | None = None) -> Organization:
        sql = "SELECT * FROM organizations WHERE org_id = ?"
        row = self.db.fetchone(sql, (str(org_id),))
        if not row:
            raise NotFoundError(f"Org {org_id} not found")
        created = datetime.fromisoformat(row["created_at"]) if "T" in str(row["created_at"]) else datetime.now(UTC)
        return Organization(
            org_id=OrgId(row["org_id"]),
            name=row["name"],
            created_at=created,
            license_ref=row["license_ref"],
        )

    def update(self, org: Organization, caller_org: OrgId | None = None) -> Organization:
        sql = "UPDATE organizations SET name = ?, license_ref = ? WHERE org_id = ?"
        self.db.execute(sql, (org.name, org.license_ref, str(org.org_id)))
        return org

    def list_all(self) -> list[Organization]:
        sql = "SELECT * FROM organizations"
        rows = self.db.fetchall(sql)
        orgs = []
        for r in rows:
            created = datetime.fromisoformat(r["created_at"]) if "T" in str(r["created_at"]) else datetime.now(UTC)
            orgs.append(Organization(
                org_id=OrgId(r["org_id"]),
                name=r["name"],
                created_at=created,
                license_ref=r["license_ref"],
            ))
        return orgs


class SqliteMembershipRepository:
    """Persistent SQLite-backed organization membership store."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def create(self, membership: Membership) -> Membership:
        sql = "INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)"
        self.db.execute(sql, (str(membership.org_id), str(membership.user_id), membership.role.value))
        return membership

    def get(self, org_id: OrgId, user_id: UserId) -> Membership:
        sql = "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?"
        row = self.db.fetchone(sql, (str(org_id), str(user_id)))
        if not row:
            raise NotFoundError(f"Membership not found for user {user_id} in org {org_id}")
        return Membership(
            org_id=OrgId(row["org_id"]),
            user_id=UserId(row["user_id"]),
            role=OrganizationRole(row["role"]),
        )

    def update(self, membership: Membership) -> Membership:
        sql = "UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?"
        self.db.execute(sql, (membership.role.value, str(membership.org_id), str(membership.user_id)))
        return membership

    def delete(self, org_id: OrgId, user_id: UserId) -> None:
        sql = "DELETE FROM memberships WHERE org_id = ? AND user_id = ?"
        self.db.execute(sql, (str(org_id), str(user_id)))

    def memberships_for(self, org_id: OrgId) -> list[Membership]:
        sql = "SELECT * FROM memberships WHERE org_id = ?"
        rows = self.db.fetchall(sql, (str(org_id),))
        return [
            Membership(
                org_id=OrgId(r["org_id"]),
                user_id=UserId(r["user_id"]),
                role=OrganizationRole(r["role"]),
            )
            for r in rows
        ]

    def orgs_for_user(self, user_id: UserId) -> list[Membership]:
        sql = "SELECT * FROM memberships WHERE user_id = ?"
        rows = self.db.fetchall(sql, (str(user_id),))
        return [
            Membership(
                org_id=OrgId(r["org_id"]),
                user_id=UserId(r["user_id"]),
                role=OrganizationRole(r["role"]),
            )
            for r in rows
        ]

    def role_of(self, org_id: OrgId, user_id: UserId) -> OrganizationRole | None:
        sql = "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?"
        row = self.db.fetchone(sql, (str(org_id), str(user_id)))
        if not row:
            return None
        return OrganizationRole(row["role"])


class SqliteUserRepository:
    """Persistent SQLite-backed user identity store."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def add(self, user: User) -> None:
        sql = """
        INSERT INTO users (user_id, email, password_hash, display_name, created_at)
        VALUES (?, ?, ?, ?, ?)
        """
        created_str = user.created_at.isoformat() if hasattr(user.created_at, "isoformat") else str(user.created_at)
        self.db.execute(sql, (str(user.user_id), user.email.lower(), user.password_hash, user.display_name, created_str))

    def get_by_email(self, email: str) -> User | None:
        sql = "SELECT * FROM users WHERE email = ?"
        row = self.db.fetchone(sql, (email.lower(),))
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"]) if "T" in str(row["created_at"]) else datetime.now(UTC)
        return User(
            user_id=UserId(row["user_id"]),
            email=row["email"],
            password_hash=row["password_hash"],
            display_name=row["display_name"],
            created_at=created,
        )

    def get(self, user_id: UserId | str) -> User | None:
        sql = "SELECT * FROM users WHERE user_id = ?"
        row = self.db.fetchone(sql, (str(user_id),))
        if not row:
            return None
        created = datetime.fromisoformat(row["created_at"]) if "T" in str(row["created_at"]) else datetime.now(UTC)
        return User(
            user_id=UserId(row["user_id"]),
            email=row["email"],
            password_hash=row["password_hash"],
            display_name=row["display_name"],
            created_at=created,
        )


class SqliteWorkflowRepository:
    """Persistent SQLite-backed visual workflow store with concurrency versioning (D18)."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def save(
        self,
        workflow: Workflow,
        org_id: OrgId | str,
        expected_version: int | None = None,
        created_by: str | None = None,
    ) -> Workflow:
        self._ensure_org(str(org_id))
        existing = self.db.fetchone(
            "SELECT version, created_at FROM workflows WHERE workflow_id = ? AND org_id = ?",
            (workflow.id, str(org_id)),
        )
        now_iso = datetime.now(UTC).isoformat()
        created_at_val = existing["created_at"] if existing else (workflow.created_at or now_iso)

        if existing is not None:
            curr_ver = int(existing["version"])
            if expected_version is not None and expected_version != curr_ver:
                raise ConflictError(
                    f"Workflow version conflict: expected {expected_version}, current database version is {curr_ver}."
                )
            new_version = curr_ver + 1
        else:
            new_version = workflow.version or 1

        workflow_dict = workflow.model_dump() if hasattr(workflow, "model_dump") else workflow.__dict__
        nodes_json = json.dumps(workflow_dict.get("nodes", []))
        edges_json = json.dumps(workflow_dict.get("edges", []))

        sql = """
        INSERT INTO workflows (
            workflow_id, org_id, name, agent_id, enabled, priority, version,
            nodes_json, edges_json, created_by, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(org_id, workflow_id) DO UPDATE SET
            name = excluded.name,
            agent_id = excluded.agent_id,
            enabled = excluded.enabled,
            priority = excluded.priority,
            version = excluded.version,
            nodes_json = excluded.nodes_json,
            edges_json = excluded.edges_json,
            updated_at = excluded.updated_at
        """
        self.db.execute(sql, (
            workflow.id,
            str(org_id),
            workflow.name,
            workflow.agent_id,
            1 if workflow.enabled else 0,
            workflow.priority if hasattr(workflow, "priority") else 100,
            new_version,
            nodes_json,
            edges_json,
            created_by,
            created_at_val,
            now_iso,
        ))

        return self.get(workflow.id, org_id) or workflow

    def save_workflow(self, org_id: OrgId | str, workflow: Workflow, created_by: str | None = None, expected_version: int | None = None) -> Workflow:
        """Alias for save with (org_id, workflow) argument order."""
        return self.save(workflow=workflow, org_id=org_id, created_by=created_by, expected_version=expected_version)

    def get(self, workflow_id: str, org_id: OrgId | str) -> Workflow | None:
        sql = "SELECT * FROM workflows WHERE workflow_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (workflow_id, str(org_id)))
        if not row:
            return None
        return self._row_to_workflow(row)

    def list_for_org(self, org_id: OrgId | str) -> list[Workflow]:
        sql = "SELECT * FROM workflows WHERE org_id = ? ORDER BY priority ASC, created_at ASC"
        rows = self.db.fetchall(sql, (str(org_id),))
        if not rows:
            for seed in self._default_seeds():
                self.save(seed, org_id)
            rows = self.db.fetchall(sql, (str(org_id),))
        return [self._row_to_workflow(r) for r in rows]

    def _default_seeds(self) -> list[Workflow]:
        return [
            Workflow(
                id="wf-auto-contain",
                name="Automated Critical Containment Gate",
                enabled=False,
                priority=10,
                nodes=[
                    WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 10}, x=0, y=0),
                    WorkflowNode(id="n2", type="condition_severity", config={"min_level": 12}, x=200, y=0),
                    WorkflowNode(id="n3", type="condition_approval", config={"required_role": "admin", "prompt_message": "Approve critical workstation isolation"}, x=400, y=0),
                    WorkflowNode(id="n4", type="tool_isolate", config={"force_override": False}, x=600, y=0),
                ],
                edges=[
                    WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                    WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
                    WorkflowEdge(id="e3", source="n3", target="n4", source_handle="true"),
                ],
            ),
            Workflow(
                id="wf-slack-notify",
                name="Triage & Slack Escalation",
                enabled=False,
                priority=50,
                nodes=[
                    WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}, x=0, y=0),
                    WorkflowNode(id="n2", type="agent_llm", config={"persona_instructions": ""}, x=200, y=0),
                    WorkflowNode(id="n3", type="tool_slack", config={"channel": "#soc-alerts"}, x=400, y=0),
                ],
                edges=[
                    WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
                    WorkflowEdge(id="e2", source="n2", target="n3", source_handle="default"),
                ],
            ),
        ]

    def list_enabled(self, org_id: OrgId | str) -> list[Workflow]:
        """Returns all enabled workflows for org, strictly ordered priority ASC, created_at ASC (D2)."""
        sql = "SELECT * FROM workflows WHERE org_id = ? AND enabled = 1 ORDER BY priority ASC, created_at ASC"
        rows = self.db.fetchall(sql, (str(org_id),))
        return [self._row_to_workflow(r) for r in rows]

    def set_enabled(self, workflow_id: str, org_id: OrgId | str, enabled: bool) -> Workflow | None:
        now_iso = datetime.now(UTC).isoformat()
        sql = "UPDATE workflows SET enabled = ?, updated_at = ? WHERE workflow_id = ? AND org_id = ?"
        cur = self.db.execute(sql, (1 if enabled else 0, now_iso, workflow_id, str(org_id)))
        if cur.rowcount == 0:
            return None
        return self.get(workflow_id, org_id)

    def delete(self, workflow_id: str, org_id: OrgId | str) -> bool:
        sql = "DELETE FROM workflows WHERE workflow_id = ? AND org_id = ?"
        cur = self.db.execute(sql, (workflow_id, str(org_id)))
        return cur.rowcount > 0

    def _row_to_workflow(self, row: dict[str, Any]) -> Workflow:
        nodes_raw = json.loads(row.get("nodes_json") or "[]")
        edges_raw = json.loads(row.get("edges_json") or "[]")
        nodes = [WorkflowNode.model_validate(n) for n in nodes_raw]
        edges = [WorkflowEdge.model_validate(e) for e in edges_raw]
        return Workflow(
            id=row["workflow_id"],
            org_id=row.get("org_id", "default"),
            name=row["name"],
            agent_id=row.get("agent_id"),
            enabled=bool(row.get("enabled", 0)),
            priority=int(row.get("priority", 100)),
            version=int(row.get("version", 1)),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
            nodes=nodes,
            edges=edges,
        )


class SqliteAgentRepository:
    """Persistent SQLite-backed SOC agent fleet repository."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def save(self, agent: SocAgent, org_id: OrgId | str) -> SocAgent:
        self._ensure_org(str(org_id))
        now_iso = agent.created_at or datetime.now(UTC).isoformat()
        sql = """
        INSERT INTO soc_agents (agent_id, org_id, name, role_description, master_prompt, status, incidents_processed, avg_sla_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(org_id, agent_id) DO UPDATE SET
            name = excluded.name,
            role_description = excluded.role_description,
            master_prompt = excluded.master_prompt,
            status = excluded.status,
            incidents_processed = excluded.incidents_processed,
            avg_sla_ms = excluded.avg_sla_ms
        """
        self.db.execute(sql, (
            agent.id, str(org_id), agent.name, agent.role_description,
            agent.master_prompt, str(agent.status.value if hasattr(agent.status, "value") else agent.status),
            agent.incidents_processed, agent.avg_sla_ms, now_iso
        ))
        return agent

    def get(self, agent_id: str, org_id: OrgId | str) -> SocAgent | None:
        sql = "SELECT * FROM soc_agents WHERE agent_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (agent_id, str(org_id)))
        if not row:
            return None
        return SocAgent(
            id=row["agent_id"],
            name=row["name"],
            role_description=row["role_description"],
            master_prompt=row["master_prompt"],
            status=row["status"],
            incidents_processed=row["incidents_processed"],
            avg_sla_ms=row["avg_sla_ms"],
            created_at=row["created_at"],
        )

    def list_for_org(self, org_id: OrgId | str) -> list[SocAgent]:
        sql = "SELECT * FROM soc_agents WHERE org_id = ? ORDER BY created_at ASC"
        rows = self.db.fetchall(sql, (str(org_id),))
        if not rows:
            for seed in self._default_seeds():
                self.save(seed, org_id)
            rows = self.db.fetchall(sql, (str(org_id),))
        return [
            SocAgent(
                id=r["agent_id"],
                name=r["name"],
                role_description=r["role_description"],
                master_prompt=r["master_prompt"],
                status=r["status"],
                incidents_processed=r["incidents_processed"],
                avg_sla_ms=r["avg_sla_ms"],
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def _default_seeds(self) -> list[SocAgent]:
        return [
            SocAgent(
                id="agent-triage",
                name="Triage Sentinel",
                role_description="Sub-millisecond alert filtering, MITRE tag correlation, and noise suppression.",
                master_prompt="You are the Triage Sentinel AI Agent. Your primary role is to inspect incoming raw SIEM telemetry from Wazuh, evaluate alert severity levels against organizational policy rules, and filter out low-level operational noise without consuming unnecessary LLM token quota.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=0.0,
                created_at="2026-09-01T00:00:00Z",
            ),
            SocAgent(
                id="agent-forensic",
                name="Forensic Investigator",
                role_description="Deep LLM evidence collection, threat intel enrichment, payload breakdown, and root cause reasoning.",
                master_prompt="You are the Forensic Investigator AI Agent. Your role is to perform deep-dive analysis on high-severity security incidents. You gather process execution trees, inspect network payload strings, correlate IOCs against threat intelligence feeds, and render structured JSON verdicts with high-confidence root cause explanations.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=0.0,
                created_at="2026-09-01T00:00:00Z",
            ),
            SocAgent(
                id="agent-containment",
                name="Containment Operator",
                role_description="Executes network boundary firewall blocks, host workstation isolations, and service credential revocations.",
                master_prompt="You are the Containment Operator AI Agent. Your role is to execute automated remediation playbooks when critical threats are identified.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=0.0,
                created_at="2026-09-01T00:00:00Z",
            ),
            SocAgent(
                id="agent-threat-hunter",
                name="Proactive Threat Hunter",
                role_description="Iteratively polls endpoints every 5 minutes for anomalous memory execution and persistence mechanisms.",
                master_prompt="You are the Proactive Threat Hunter AI Agent. You operate on a recurring scheduled loop, polling active workloads.",
                status=AgentStatus.ACTIVE,
                incidents_processed=0,
                avg_sla_ms=0.0,
                created_at="2026-09-01T00:00:00Z",
            ),
        ]

    def delete(self, agent_id: str, org_id: OrgId | str) -> bool:
        sql = "DELETE FROM soc_agents WHERE agent_id = ? AND org_id = ?"
        cur = self.db.execute(sql, (agent_id, str(org_id)))
        return cur.rowcount > 0


class SqliteWorkflowRunRepository:
    """Persistent SQLite-backed workflow execution run & node trace repository."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def create_run(
        self,
        org_id: str,
        run_id: str,
        workflow_id: str,
        alert_id: str,
        definition_snapshot: dict[str, Any] | Workflow,
        alert: dict[str, Any] | SiemAlert,
        base_report: dict[str, Any] | InvestigationReport,
        attempt: int = 1,
    ) -> dict[str, Any]:
        self._ensure_org(str(org_id))
        now_iso = datetime.now(UTC).isoformat()
        snap_json = json.dumps(definition_snapshot.model_dump() if hasattr(definition_snapshot, "model_dump") else definition_snapshot)
        alert_json = json.dumps(alert.model_dump() if hasattr(alert, "model_dump") else alert)
        report_json = json.dumps(base_report.to_dict() if hasattr(base_report, "to_dict") else base_report)

        sql = """
        INSERT INTO workflow_runs (
            run_id, workflow_id, org_id, alert_id, attempt,
            status, outcome, side_effects, unknown_outcome,
            definition_snapshot, alert_json, base_report_json,
            edge_states_json, errors_json, heartbeat_at, started_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, NULL, 0, 0, ?, ?, ?, '{}', '[]', ?, ?
        )
        """
        self.db.execute(sql, (
            run_id, workflow_id, str(org_id), alert_id, attempt,
            "RUNNING", snap_json, alert_json, report_json, now_iso, now_iso
        ))
        return self.get_run(org_id, run_id) or {}

    def get_run(self, org_id: str, run_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM workflow_runs WHERE run_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (run_id, str(org_id)))
        if not row:
            return None
        return self._format_run(row)

    def list_runs_for_org(self, org_id: str, limit: int = 50) -> list[dict[str, Any]]:
        sql = "SELECT * FROM workflow_runs WHERE org_id = ? ORDER BY started_at DESC LIMIT ?"
        rows = self.db.fetchall(sql, (str(org_id), limit))
        return [self._format_run(r) for r in rows]

    def list_for_org(self, org_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Alias for list_runs_for_org."""
        return self.list_runs_for_org(org_id, limit)

    def update_run_status(
        self,
        org_id: str,
        run_id: str,
        status: str,
        outcome: str | None = None,
        side_effects: int | None = None,
        unknown_outcome: int | None = None,
        edge_states: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        heartbeat_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        updates = ["status = ?"]
        params: list[Any] = [status]

        if outcome is not None:
            updates.append("outcome = ?")
            params.append(outcome)
        if side_effects is not None:
            updates.append("side_effects = ?")
            params.append(1 if side_effects else 0)
        if unknown_outcome is not None:
            updates.append("unknown_outcome = ?")
            params.append(1 if unknown_outcome else 0)
        if edge_states is not None:
            updates.append("edge_states_json = ?")
            params.append(json.dumps(edge_states))
        if errors is not None:
            updates.append("errors_json = ?")
            params.append(json.dumps(errors))
        if heartbeat_at is not None:
            updates.append("heartbeat_at = ?")
            params.append(heartbeat_at)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)

        sql = f"UPDATE workflow_runs SET {', '.join(updates)} WHERE run_id = ? AND org_id = ?"
        params.extend([run_id, str(org_id)])
        self.db.execute(sql, tuple(params))

    def update_run(
        self,
        org_id: str,
        run_id: str,
        status: str,
        outcome: str | None = None,
        side_effects: int | None = None,
        unknown_outcome: int | None = None,
        edge_states: dict[str, Any] | None = None,
        errors: list[str] | None = None,
        heartbeat_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        self.update_run_status(
            org_id=org_id,
            run_id=run_id,
            status=status,
            outcome=outcome,
            side_effects=side_effects,
            unknown_outcome=unknown_outcome,
            edge_states=edge_states,
            errors=errors,
            heartbeat_at=heartbeat_at,
            completed_at=completed_at,
        )

    def update_heartbeat(self, org_id: str, run_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        sql = "UPDATE workflow_runs SET heartbeat_at = ? WHERE run_id = ? AND org_id = ?"
        self.db.execute(sql, (now_iso, run_id, str(org_id)))

    def create_node_run(
        self,
        node_run_id: str,
        run_id: str,
        org_id: str,
        node_id: str,
        node_type: str,
        status: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        started_at: str,
        error_message: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        self._ensure_org(str(org_id))
        sql = """
        INSERT INTO node_runs (
            node_run_id, run_id, org_id, node_id, node_type,
            status, inputs_json, outputs_json, error_message,
            started_at, completed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute(sql, (
            node_run_id, run_id, str(org_id), node_id, node_type,
            status, json.dumps(inputs), json.dumps(outputs),
            error_message, started_at, completed_at
        ))

    def save_node_run(
        self,
        node_run_id: str,
        run_id: str,
        org_id: str,
        node_id: str,
        node_type: str,
        status: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        started_at: str,
        error_message: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        self.create_node_run(
            node_run_id=node_run_id,
            run_id=run_id,
            org_id=org_id,
            node_id=node_id,
            node_type=node_type,
            status=status,
            inputs=inputs,
            outputs=outputs,
            started_at=started_at,
            error_message=error_message,
            completed_at=completed_at,
        )

    def update_node_run(
        self,
        node_run_id: str,
        status: str,
        outputs: dict[str, Any] | None = None,
        error_message: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        updates = ["status = ?"]
        params: list[Any] = [status]
        if outputs is not None:
            updates.append("outputs_json = ?")
            params.append(json.dumps(outputs))
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)

        sql = f"UPDATE node_runs SET {', '.join(updates)} WHERE node_run_id = ?"
        params.append(node_run_id)
        self.db.execute(sql, tuple(params))

    def get_node_runs(self, org_id: str, run_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM node_runs WHERE org_id = ? AND run_id = ? ORDER BY started_at ASC"
        rows = self.db.fetchall(sql, (str(org_id), run_id))
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["inputs"] = json.loads(d.get("inputs_json") or "{}")
            except Exception:
                d["inputs"] = {}
            try:
                d["outputs"] = json.loads(d.get("outputs_json") or "{}")
            except Exception:
                d["outputs"] = {}
            result.append(d)
        return result

    def get_stale_running_runs(self, max_heartbeat_age_seconds: int = 300) -> list[dict[str, Any]]:
        now_ts = datetime.now(UTC).timestamp()
        cutoff_iso = datetime.fromtimestamp(now_ts - max_heartbeat_age_seconds, UTC).isoformat()
        sql = "SELECT * FROM workflow_runs WHERE status = 'RUNNING' AND heartbeat_at < ?"
        rows = self.db.fetchall(sql, (cutoff_iso,))
        return [self._format_run(r) for r in rows]

    def _format_run(self, row: dict[str, Any]) -> dict[str, Any]:
        d = dict(row)
        d["side_effects_executed"] = bool(d.get("side_effects", 0))
        d["unknown_outcome"] = bool(d.get("unknown_outcome", 0))
        try:
            d["definition_snapshot"] = json.loads(d.get("definition_snapshot") or "{}")
        except Exception:
            d["definition_snapshot"] = {}
        try:
            d["alert"] = json.loads(d.get("alert_json") or "{}")
        except Exception:
            d["alert"] = {}
        try:
            d["base_report"] = json.loads(d.get("base_report_json") or "{}")
        except Exception:
            d["base_report"] = {}
        try:
            d["edge_states"] = json.loads(d.get("edge_states_json") or "{}")
        except Exception:
            d["edge_states"] = {}
        try:
            d["errors"] = json.loads(d.get("errors_json") or "[]")
        except Exception:
            d["errors"] = []
        return d


class SqliteApprovalRepository:
    """Persistent SQLite-backed human approval gate repository (D14)."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def create_approval(
        self,
        approval_id: str,
        run_id: str,
        workflow_id: str,
        org_id: str,
        node_id: str,
        required_role: str = "admin",
        prompt_message: str = "Please review containment.",
        expires_at: str = "",
        created_at: str = "",
    ) -> dict[str, Any]:
        self._ensure_org(str(org_id))
        now_iso = created_at or datetime.now(UTC).isoformat()
        sql = """
        INSERT INTO workflow_approvals (
            approval_id, run_id, workflow_id, org_id, node_id,
            required_role, prompt_message, status, created_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
        """
        self.db.execute(sql, (
            approval_id, run_id, workflow_id, str(org_id), node_id,
            required_role, prompt_message, now_iso, expires_at
        ))
        return self.get_approval(org_id, approval_id) or {}

    def get_approval(self, org_id: str, approval_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM workflow_approvals WHERE approval_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (approval_id, str(org_id)))
        return dict(row) if row else None

    def get_pending_approval_for_node(self, org_id: str, run_id: str, node_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM workflow_approvals WHERE org_id = ? AND run_id = ? AND node_id = ? AND status = 'PENDING'"
        row = self.db.fetchone(sql, (str(org_id), run_id, node_id))
        return dict(row) if row else None

    def list_pending(self, org_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM workflow_approvals WHERE org_id = ? AND status = 'PENDING' ORDER BY created_at DESC"
        rows = self.db.fetchall(sql, (str(org_id),))
        return [dict(r) for r in rows]

    def list_for_run(self, org_id: str, run_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM workflow_approvals WHERE org_id = ? AND run_id = ? ORDER BY created_at ASC"
        rows = self.db.fetchall(sql, (str(org_id), run_id))
        return [dict(r) for r in rows]

    def resolve_approval(
        self,
        org_id: str,
        approval_id: str,
        status: str,  # "APPROVED", "REJECTED", "EXPIRED"
        resolved_by: str,
        resolved_at: str = "",
    ) -> bool:
        now_iso = resolved_at or datetime.now(UTC).isoformat()
        sql = """
        UPDATE workflow_approvals
        SET status = ?, resolved_by = ?, resolved_at = ?
        WHERE approval_id = ? AND org_id = ? AND status = 'PENDING'
        """
        cur = self.db.execute(sql, (status, resolved_by, now_iso, approval_id, str(org_id)))
        return cur.rowcount > 0

    def get_expired_pending_approvals(self, now_iso: str = "") -> list[dict[str, Any]]:
        now_str = now_iso or datetime.now(UTC).isoformat()
        sql = "SELECT * FROM workflow_approvals WHERE status = 'PENDING' AND expires_at < ?"
        rows = self.db.fetchall(sql, (now_str,))
        return [dict(r) for r in rows]


class SqliteAlertClaimRepository:
    """Persistent SQLite-backed idempotent alert claim store (D5)."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def claim_alert(self, org_id: str, alert_id: str, claimed_at: str = "") -> tuple[bool, dict[str, Any] | None]:
        self._ensure_org(str(org_id))
        now_iso = claimed_at or datetime.now(UTC).isoformat()
        try:
            sql = """
            INSERT INTO alert_claims (org_id, alert_id, attempt, status, outcome, side_effects, claimed_at)
            VALUES (?, ?, 1, 'RUNNING', NULL, 0, ?)
            """
            self.db.execute(sql, (str(org_id), alert_id, now_iso))
            return True, self.get_claim(org_id, alert_id)
        except sqlite3.IntegrityError:
            return False, self.get_claim(org_id, alert_id)

    def get_claim(self, org_id: str, alert_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM alert_claims WHERE org_id = ? AND alert_id = ?"
        row = self.db.fetchone(sql, (str(org_id), alert_id))
        if not row:
            return None
        d = dict(row)
        try:
            d["report"] = json.loads(d.get("report_json") or "{}") if d.get("report_json") else None
        except Exception:
            d["report"] = None
        return d

    def reclaim_alert_if_failed_before_side_effects(
        self,
        org_id: str,
        alert_id: str,
        claimed_at: str = "",
    ) -> tuple[bool, dict[str, Any] | None]:
        """Atomically re-claims alert if prior run had no side effects (D5)."""
        now_iso = claimed_at or datetime.now(UTC).isoformat()
        sql = """
        UPDATE alert_claims
        SET attempt = attempt + 1, status = 'RUNNING', outcome = NULL, claimed_at = ?
        WHERE org_id = ? AND alert_id = ?
          AND (outcome = 'FAILED_BEFORE_SIDE_EFFECTS' OR (outcome = 'INTERRUPTED' AND side_effects = 0))
        """
        cur = self.db.execute(sql, (now_iso, str(org_id), alert_id))
        return (cur.rowcount > 0), self.get_claim(org_id, alert_id)

    def update_claim_status(
        self,
        org_id: str,
        alert_id: str,
        status: str,
        outcome: str,
        side_effects: int,
        report: InvestigationReport | dict[str, Any] | None,
        incident_id: str | None = None,
        completed_at: str = "",
    ) -> None:
        now_iso = completed_at or datetime.now(UTC).isoformat()
        report_json = json.dumps(report.to_dict() if hasattr(report, "to_dict") else report) if report else None

        sql = """
        UPDATE alert_claims
        SET status = ?, outcome = ?, side_effects = ?, report_json = ?, incident_id = ?, completed_at = ?
        WHERE org_id = ? AND alert_id = ?
        """
        self.db.execute(sql, (
            status, outcome, 1 if side_effects else 0, report_json, incident_id, now_iso, str(org_id), alert_id
        ))


class SqliteAllowlistRepository:
    """Persistent SQLite-backed containment safety allowlist store (D12)."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def add_entry(
        self,
        entry_id: str,
        org_id: str,
        kind: str,
        value: str,
        note: str | None = None,
        created_by: str | None = None,
        created_at: str = "",
    ) -> dict[str, Any]:
        self._ensure_org(str(org_id))
        now_iso = created_at or datetime.now(UTC).isoformat()
        sql = """
        INSERT INTO containment_allowlist (entry_id, org_id, kind, value, note, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute(sql, (entry_id, str(org_id), kind, value.strip(), note, created_by, now_iso))
        row = self.db.fetchone("SELECT * FROM containment_allowlist WHERE entry_id = ?", (entry_id,))
        return dict(row) if row else {}

    def is_allowlisted(self, org_id: str, target_value: str) -> bool:
        val = target_value.strip().lower()
        sql = "SELECT 1 FROM containment_allowlist WHERE org_id = ? AND LOWER(value) = ? LIMIT 1"
        row = self.db.fetchone(sql, (str(org_id), val))
        return row is not None

    def list_entries(self, org_id: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM containment_allowlist WHERE org_id = ? ORDER BY created_at DESC"
        rows = self.db.fetchall(sql, (str(org_id),))
        return [dict(r) for r in rows]

    def delete_entry(self, org_id: str, entry_id: str) -> bool:
        sql = "DELETE FROM containment_allowlist WHERE entry_id = ? AND org_id = ?"
        cur = self.db.execute(sql, (entry_id, str(org_id)))
        return cur.rowcount > 0


class SqliteActionLogRepository:
    """Persistent SQLite-backed action log repository for AI agents, workflows, and guardrails."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def _ensure_org(self, org_id: str) -> None:
        now_iso = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", now_iso),
        )

    def record_action(
        self,
        org_id: str,
        actor_type: str,
        actor_name: str,
        action_type: str,
        status: str,
        summary: str,
        target: str | None = None,
        details: dict[str, Any] | None = None,
        incident_id: str | None = None,
        alert_id: str | None = None,
        timestamp: str = "",
    ) -> dict[str, Any]:
        self._ensure_org(str(org_id))
        action_id = f"act-{secrets.token_hex(6)}"
        now_iso = timestamp or datetime.now(UTC).isoformat()
        details_json = json.dumps(details or {})

        sql = """
        INSERT INTO action_logs (
            action_id, org_id, timestamp, actor_type, actor_name,
            action_type, target, status, summary, details_json,
            incident_id, alert_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self.db.execute(sql, (
            action_id, str(org_id), now_iso, actor_type, actor_name,
            action_type, target or "", status, summary, details_json,
            incident_id, alert_id,
        ))

        row = self.db.fetchone("SELECT * FROM action_logs WHERE action_id = ?", (action_id,))
        res = dict(row) if row else {}
        if res.get("details_json"):
            try:
                res["details"] = json.loads(res["details_json"])
            except Exception:
                res["details"] = {}
        return res

    def list_actions(
        self,
        org_id: str,
        limit: int = 100,
        actor_type: str | None = None,
        action_type: str | None = None,
    ) -> list[dict[str, Any]]:
        self._ensure_org(str(org_id))
        params: list[Any] = [str(org_id)]
        clauses: list[str] = ["org_id = ?"]

        if actor_type and actor_type != "all":
            clauses.append("actor_type = ?")
            params.append(actor_type)
        if action_type and action_type != "all":
            clauses.append("action_type = ?")
            params.append(action_type)

        where_str = " AND ".join(clauses)
        sql = f"SELECT * FROM action_logs WHERE {where_str} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(sql, tuple(params))
        items: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            if d.get("details_json"):
                try:
                    d["details"] = json.loads(d["details_json"])
                except Exception:
                    d["details"] = {}
            items.append(d)

        # If few direct logs exist, dynamically supplement from node_runs, approvals, and incidents
        if len(items) < 50:
            existing_ids = {item["action_id"] for item in items}

            # Supplement from node runs
            node_sql = """
            SELECT nr.node_run_id, nr.run_id, nr.node_id, nr.node_type, nr.status,
                   nr.started_at, nr.completed_at, nr.inputs_json, nr.outputs_json, nr.error_message,
                   wr.workflow_id, wr.alert_id, wr.incident_id, wr.definition_snapshot
            FROM node_runs nr
            JOIN workflow_runs wr ON nr.run_id = wr.run_id
            WHERE nr.org_id = ?
            ORDER BY nr.started_at DESC
            LIMIT ?
            """
            for nr in self.db.fetchall(node_sql, (str(org_id), limit)):
                act_id = f"act-node-{nr['node_run_id']}"
                if act_id in existing_ids:
                    continue
                node_type = nr["node_type"]
                ntype_name = node_type.replace("_", " ").title()

                # Derive actor and action name
                actor_name = "Automated Playbook"
                try:
                    snap = json.loads(nr.get("definition_snapshot") or "{}")
                    if snap.get("name"):
                        actor_name = snap["name"]
                except Exception:
                    pass

                summary = f"Executed {ntype_name} node ({nr['node_id']})"
                if nr.get("error_message"):
                    summary += f" - {nr['error_message']}"

                target = ""
                try:
                    inputs = json.loads(nr.get("inputs_json") or "{}")
                    target = inputs.get("agent_name") or inputs.get("host") or inputs.get("src_ip") or ""
                except Exception:
                    pass

                items.append({
                    "action_id": act_id,
                    "org_id": str(org_id),
                    "timestamp": nr["completed_at"] or nr["started_at"],
                    "actor_type": "agent" if "agent" in node_type else "workflow",
                    "actor_name": actor_name,
                    "action_type": node_type.upper(),
                    "target": target,
                    "status": nr["status"],
                    "summary": summary,
                    "details": {},
                    "incident_id": nr.get("incident_id"),
                    "alert_id": nr.get("alert_id"),
                })
                existing_ids.add(act_id)

            # Supplement from incidents
            inc_sql = "SELECT * FROM incidents WHERE org_id = ? ORDER BY created_at DESC LIMIT ?"
            for inc in self.db.fetchall(inc_sql, (str(org_id), limit)):
                act_id = f"act-inc-{inc['ticket_id']}"
                if act_id in existing_ids:
                    continue
                items.append({
                    "action_id": act_id,
                    "org_id": str(org_id),
                    "timestamp": inc["created_at"],
                    "actor_type": "agent",
                    "actor_name": "Triage Sentinel AI" if inc["policy_tier"] == "triage" else "Forensic Hunter",
                    "action_type": "INVESTIGATION_ASSESSMENT",
                    "target": inc["agent_name"] or inc["rule_id"] or "Endpoint",
                    "status": "COMPLETED",
                    "summary": f"Generated forensic verdict: {inc['summary'][:100]}...",
                    "details": {"severity": inc["severity"], "policy_tier": inc["policy_tier"]},
                    "incident_id": inc["ticket_id"],
                    "alert_id": inc["alert_id"],
                })
                existing_ids.add(act_id)

            # Sort combined items by timestamp descending
            items.sort(key=lambda x: str(x.get("timestamp") or ""), reverse=True)

        return items[:limit]

