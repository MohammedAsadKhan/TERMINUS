"""Persistence repositories for TERMINUS 2.0.

Provides robust SQLite-backed stores for Incidents, Organizations, Users,
Memberships, SocAgents, Workflows, DetectionRules, and AuditLogs.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Any

from terminus.auth.models import User
from terminus.core.base import NotFoundError
from terminus.core.ids import OrgId, TicketId, UserId
from terminus.models import (
    InvestigationReport,
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
        self.db = db or Database.get_instance()

    async def create_ticket(
        self,
        report: InvestigationReport,
        org_id: OrgId,
        evidence_citations: list[dict[str, Any]] | None = None,
        raw_payload: dict[str, Any] | None = None,
    ) -> TicketId:
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

        # Ensure org exists in db
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) VALUES (?, ?, ?, ?, ?)",
            (str(org_id), f"Organization {org_id}", now_iso, "", "{}"),
        )

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
        self.db = db or Database.get_instance()

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
        self.db = db or Database.get_instance()

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
        self.db = db or Database.get_instance()

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
    """Persistent SQLite-backed visual workflow store."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database.get_instance()

    def save(self, workflow: Workflow, org_id: OrgId | str) -> Workflow:
        nodes_json = json.dumps([n.model_dump() for n in workflow.nodes])
        edges_json = json.dumps([e.model_dump() for e in workflow.edges])
        now_iso = datetime.now(UTC).isoformat()
        sql = """
        INSERT INTO workflows (workflow_id, org_id, name, agent_id, enabled, nodes_json, edges_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(workflow_id) DO UPDATE SET
            name = excluded.name,
            agent_id = excluded.agent_id,
            enabled = excluded.enabled,
            nodes_json = excluded.nodes_json,
            edges_json = excluded.edges_json,
            updated_at = excluded.updated_at
        """
        self.db.execute(sql, (
            workflow.id, str(org_id), workflow.name, workflow.agent_id,
            1 if workflow.enabled else 0, nodes_json, edges_json, now_iso, now_iso
        ))
        return workflow

    def get(self, workflow_id: str, org_id: OrgId | str) -> Workflow | None:
        sql = "SELECT * FROM workflows WHERE workflow_id = ? AND org_id = ?"
        row = self.db.fetchone(sql, (workflow_id, str(org_id)))
        if not row:
            return None
        return self._row_to_workflow(row)

    def list_for_org(self, org_id: OrgId | str) -> list[Workflow]:
        sql = "SELECT * FROM workflows WHERE org_id = ?"
        rows = self.db.fetchall(sql, (str(org_id),))
        return [self._row_to_workflow(r) for r in rows]

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
            name=row["name"],
            agent_id=row.get("agent_id"),
            enabled=bool(row.get("enabled", 1)),
            nodes=nodes,
            edges=edges,
        )


class SqliteAgentRepository:
    """Persistent SQLite-backed SOC agent fleet repository."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database.get_instance()

    def save(self, agent: SocAgent, org_id: OrgId | str) -> SocAgent:
        now_iso = agent.created_at or datetime.now(UTC).isoformat()
        sql = """
        INSERT INTO soc_agents (agent_id, org_id, name, role_description, master_prompt, status, incidents_processed, avg_sla_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
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
        sql = "SELECT * FROM soc_agents WHERE org_id = ?"
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

    def delete(self, agent_id: str, org_id: OrgId | str) -> bool:
        sql = "DELETE FROM soc_agents WHERE agent_id = ? AND org_id = ?"
        cur = self.db.execute(sql, (agent_id, str(org_id)))
        return cur.rowcount > 0
