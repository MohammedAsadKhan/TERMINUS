"""Live response decisions, isolated from fixture approvals and provider receipts."""

# pyright: basic
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any
from uuid import uuid4

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.storage import OrchestrationStore
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.response.registry import CAPABILITIES
from terminus.response.storage import canonical, digest
from terminus.response.wazuh_transport import WazuhBlockRequest, WazuhResponseTransport
from terminus.storage.db import Database
from terminus.toolkit.sources import ReadCollection

TERMINAL = {"recovered", "recovered_unverified", "denied", "unavailable", "cancelled"}
CLOSED = {"RESOLVED", "CLOSED"}


class ResponseConflictError(ValueError):
    pass


class LiveResponseService:
    def __init__(
        self, db: Database, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.db = db
        self.clock = clock or (lambda: datetime.now(UTC))
        with db.transaction() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_source_receipts (org_id TEXT NOT NULL, incident_id TEXT NOT NULL, evidence_id TEXT PRIMARY KEY, content_hash TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_control (id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_adapter_binding (adapter TEXT PRIMARY KEY, org_id TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_runtime (org_id TEXT PRIMARY KEY, heartbeat TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_proposals (proposal_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(org_id,incident_id,digest))"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_decisions (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, proposal_id TEXT NOT NULL, actor TEXT NOT NULL, decision TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_authorizations (authorization_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, proposal_id TEXT NOT NULL, actor TEXT NOT NULL, mode TEXT NOT NULL, scope TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_intents (intent_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, proposal_id TEXT NOT NULL UNIQUE, authorization_id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_observations (id INTEGER PRIMARY KEY, intent_id TEXT, phase TEXT NOT NULL, verified INTEGER NOT NULL, observed_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS live_response_events (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, proposal_id TEXT, intent_id TEXT, state TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS live_response_proposal_immutable BEFORE UPDATE ON live_response_proposals BEGIN SELECT RAISE(ABORT,'immutable live proposal'); END"
            )

            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS live_response_close_revoke AFTER UPDATE OF status ON incidents WHEN upper(NEW.status) IN ('CLOSED','RESOLVED') BEGIN UPDATE live_response_authorizations SET revoked_at=COALESCE(revoked_at,strftime('%Y-%m-%dT%H:%M:%f+00:00','now')) WHERE org_id=NEW.org_id AND incident_id=NEW.ticket_id; END"
            )

            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS live_response_auth_immutable BEFORE UPDATE OF org_id,incident_id,proposal_id,actor,mode,scope,expires_at ON live_response_authorizations BEGIN SELECT RAISE(ABORT,'immutable response authorization'); END"
            )
            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS live_response_decision_immutable BEFORE UPDATE ON live_response_decisions BEGIN SELECT RAISE(ABORT,'immutable response decision'); END"
            )

            conn.execute(
                "CREATE TRIGGER IF NOT EXISTS live_response_close_audit AFTER UPDATE OF status ON incidents WHEN upper(NEW.status) IN ('CLOSED','RESOLVED') AND upper(OLD.status) NOT IN ('CLOSED','RESOLVED') AND EXISTS(SELECT 1 FROM live_response_authorizations WHERE org_id=NEW.org_id AND incident_id=NEW.ticket_id) BEGIN INSERT INTO live_response_events(org_id,incident_id,state,detail,created_at) VALUES(NEW.org_id,NEW.ticket_id,'revoked','Incident closed; response authorization revoked',strftime('%Y-%m-%dT%H:%M:%f+00:00','now')); END"
            )

    def record_source(self, org: str, incident: str, evidence_id: str) -> None:
        """Trusted reader/import path only; never exposed as an operator or model API."""
        record = next(
            (
                r
                for r in OrchestrationStore(self.db).list_evidence(
                    org, incident_id=incident
                )
                if r.evidence_id == evidence_id
            ),
            None,
        )
        if record is None or record.source != "source.wazuh_import":
            raise ValueError("Canonical source record required")
        self.db.execute(
            "INSERT OR IGNORE INTO live_response_source_receipts VALUES(?,?,?,?)",
            (org, incident, evidence_id, digest(record.content)),
        )

    def _incident(self, org: str, incident: str) -> dict[str, Any]:
        row = self.db.fetchone(
            "SELECT * FROM incidents WHERE org_id=? AND ticket_id=?", (org, incident)
        )
        if not row:
            raise LookupError("Incident not found")
        return row

    def require_admin(self, org: str, actor: str) -> None:
        if (
            SqliteMembershipStore(self.db).role_of(OrgId(org), UserId(actor))
            != OrganizationRole.ADMIN
        ):
            raise PermissionError("Current organization administrator required")

    def _event(
        self,
        org: str,
        incident: str,
        proposal: str | None,
        state: str,
        detail: str,
        intent: str | None = None,
    ) -> None:
        self.db.execute(
            "INSERT INTO live_response_events(org_id,incident_id,proposal_id,intent_id,state,detail,created_at) VALUES(?,?,?,?,?,?,?)",
            (org, incident, proposal, intent, state, detail, self.clock().isoformat()),
        )

    def takeover(self, org: str) -> None:
        """Permanently fence the old standalone dispatcher before console execution."""
        with self.db.transaction() as conn:
            binding = conn.execute(
                "SELECT org_id FROM live_response_adapter_binding WHERE adapter='isolated-wazuh-lab'"
            ).fetchone()
            if binding and binding["org_id"] != org:
                raise ResponseConflictError(
                    "This lab adapter is already bound to another organization"
                )
            conn.execute(
                "INSERT OR IGNORE INTO live_response_adapter_binding VALUES('isolated-wazuh-lab',?)",
                (org,),
            )
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name='autonomous_lab_intents'"
            ).fetchone()
            if (
                exists
                and conn.execute(
                    "SELECT 1 FROM autonomous_lab_intents WHERE state NOT IN ('recovered','recovered_unverified','denied','unavailable')"
                ).fetchone()
            ):
                raise ResponseConflictError(
                    "Reconcile the standalone controller before enabling live response"
                )
            conn.execute(
                "INSERT INTO live_response_control VALUES(1,'console') ON CONFLICT(id) DO UPDATE SET mode='console'"
            )
            conn.execute(
                "INSERT INTO live_response_runtime VALUES(?,?) ON CONFLICT(org_id) DO UPDATE SET heartbeat=excluded.heartbeat",
                (org, self.clock().isoformat()),
            )

    def ready(self, org: str) -> bool:
        row = self.db.fetchone(
            "SELECT heartbeat FROM live_response_runtime WHERE org_id=?", (org,)
        )
        return bool(
            row
            and 0
            <= (self.clock() - datetime.fromisoformat(row["heartbeat"])).total_seconds()
            < 15
        )

    def refresh(self, org: str, incident: str) -> str:
        incident_record = self._incident(org, incident)
        records = OrchestrationStore(self.db).list_evidence(org, incident_id=incident)
        observations = {}
        citations = {}
        fim = False
        for record in records:
            if record.source != "source.wazuh_import" or not isinstance(
                record.content, dict
            ):
                continue
            raw_data = record.content.get("data", {})
            raw_alert = raw_data.get("alert", {}) if isinstance(raw_data, dict) else {}
            if isinstance(raw_alert, dict) and isinstance(raw_alert.get("rule"), dict):
                fim |= "syscheck" in raw_alert["rule"].get("groups", [])
            trusted = self.db.fetchone(
                "SELECT content_hash FROM live_response_source_receipts WHERE org_id=? AND incident_id=? AND evidence_id=?",
                (org, incident, record.evidence_id),
            )
            if not trusted or trusted["content_hash"] != digest(record.content):
                continue
            data = record.content.get("data", {})
            alert = data.get("alert", {}) if isinstance(data, dict) else {}
            agent = alert.get("agent", {})
            rule = alert.get("rule", {})
            fim |= "syscheck" in rule.get("groups", [])
            if (
                agent.get("id"),
                agent.get("ip"),
                alert.get("data", {}).get("srcip"),
            ) != ("001", "10.77.0.20", "10.77.0.10"):
                continue
            if not {"sshd", "authentication_failed"} <= set(rule.get("groups", [])):
                continue
            try:
                stamp = datetime.fromisoformat(alert["timestamp"])
                if stamp.tzinfo is None:
                    continue
                key = record.content["source_event_id"]
                observations[key] = stamp.isoformat()
                citations[key] = {
                    "id": record.evidence_id,
                    "hash": digest(record.content),
                    "task_id": record.task_id,
                }
            except (KeyError, ValueError, TypeError):
                continue
        fresh = {
            key: stamp
            for key, stamp in observations.items()
            if 0
            <= (self.clock() - datetime.fromisoformat(stamp)).total_seconds()
            <= 120
        }
        selected = fresh if len(fresh) >= 3 else observations
        executable = len(selected) >= 3 and not fim
        payload = {
            "suggested_steps": json.loads(
                incident_record.get("recommended_actions") or "[]"
            ),
            "origin": "system",
            "creator_id": None,
            "action": "response.wazuh_ip_block"
            if executable
            else "recommendation.review",
            "title": "Temporarily block the SSH source"
            if executable
            else "Review file changes"
            if fim
            else "Review incident evidence",
            "rationale": "Repeated failed SSH authentication; compromise is not established."
            if executable
            else "Confirm authorization and preserve evidence before choosing a connected response.",
            "agent_id": "001" if executable else None,
            "target_ip": "10.77.0.20" if executable else None,
            "source_ip": "10.77.0.10" if executable else None,
            "duration_seconds": 60,
            "cooldown_seconds": 300,
            "max_actions": 3,
            "threshold": 3,
            "event_ids": sorted(selected) if executable else [],
            "timestamps": selected if executable else {},
            "evidence": [citations[key] for key in sorted(selected)]
            if executable
            else [
                {"id": r.evidence_id, "hash": digest(r.content), "task_id": r.task_id}
                for r in records[:16]
            ],
            "impact": "Inbound traffic from 10.77.0.10 to this target is denied for 60 seconds; management must remain reachable."
            if executable
            else "Review only; no executable adapter is available for this recommendation.",
            "verification": "Independent Kali SSH probe, Windows management SSH, and action-owned nftables set."
            if executable
            else "Review the cited records and trusted baseline.",
            "recovery": "Kernel timeout followed by independent recovery checks."
            if executable
            else "File restoration execution unavailable"
            if fim
            else "No automated recovery configured",
            "exclusions": [
                "management addresses",
                "all other sources",
                "all other agents",
            ],
        }
        fingerprint = digest(payload)
        with self.db.transaction():
            old = self.db.fetchone(
                "SELECT proposal_id FROM live_response_proposals WHERE org_id=? AND incident_id=? AND digest=?",
                (org, incident, fingerprint),
            )
            if old:
                return old["proposal_id"]
            proposal = str(uuid4())
            self.db.execute(
                "INSERT INTO live_response_proposals VALUES(?,?,?,?,?,?)",
                (
                    proposal,
                    org,
                    incident,
                    fingerprint,
                    canonical(payload),
                    self.clock().isoformat(),
                ),
            )
            self._event(
                org,
                incident,
                proposal,
                "recommended",
                "System recommendation saved from canonical evidence; no response executed",
            )
            return proposal

    def ingest(self, org: str, actor: str, collection: ReadCollection) -> str | None:  # noqa: C901 -- fixed trusted-source admission
        """Trusted polling intake: link authorized work or prepare a new pending incident."""
        self.require_admin(org, actor)
        if (
            collection.status != "ok"
            or collection.coverage != "complete"
            or collection.truncated
            or collection.gaps
        ):
            return None
        with self.db.transaction():
            if self.link_fresh_observations(org, collection):
                return None
            if self.db.fetchone(
                "SELECT 1 FROM live_response_authorizations WHERE org_id=? AND mode='autonomy' AND revoked_at IS NULL AND expires_at>?",
                (org, self.clock().isoformat()),
            ):
                return None
            seen = {
                event
                for row in self.db.fetchall(
                    "SELECT payload FROM live_response_proposals WHERE org_id=?", (org,)
                )
                for event in json.loads(row["payload"]).get("event_ids", [])
            }
            selected = []
            for observation in collection.observations:
                if (
                    observation.source_id != "wazuh-indexer"
                    or observation.source_event_id in seen
                    or not isinstance(observation.data, dict)
                ):
                    continue
                alert = observation.data.get("alert", {})
                if not isinstance(alert, dict):
                    continue
                if (
                    alert.get("agent", {}).get("id"),
                    alert.get("agent", {}).get("ip"),
                    alert.get("data", {}).get("srcip"),
                ) != ("001", "10.77.0.20", "10.77.0.10"):
                    continue
                if not {"sshd", "authentication_failed"} <= set(
                    alert.get("rule", {}).get("groups", [])
                ):
                    continue
                try:
                    stamp = datetime.fromisoformat(alert["timestamp"])
                except (ValueError, KeyError, TypeError):
                    continue
                if (
                    stamp.tzinfo is None
                    or not 0 <= (self.clock() - stamp).total_seconds() <= 120
                ):
                    continue
                selected.append(observation)
            if len({o.source_event_id for o in selected}) < 3:
                return None
            from terminus.toolkit.lab_import import import_authentication_incident

            return import_authentication_incident(
                self.db,
                org_id=org,
                actor=actor,
                agent_id="001",
                collection=ReadCollection(
                    status="ok", coverage="complete", observations=tuple(selected)
                ),
            )

    def link_fresh_observations(self, org: str, collection: ReadCollection) -> int:  # noqa: C901, PLR0912 -- ordered source admission
        """Correlate authenticated matching source records only to one active incident authorization."""
        if (
            collection.status != "ok"
            or collection.coverage != "complete"
            or collection.truncated
            or collection.gaps
        ):
            return 0
        auths = self.db.fetchall(
            "SELECT * FROM live_response_authorizations WHERE org_id=? AND mode='autonomy' AND revoked_at IS NULL AND expires_at>?",
            (org, self.clock().isoformat()),
        )
        if len(auths) != 1:
            return 0
        auth = auths[0]
        incident = auth["incident_id"]
        if self._incident(org, incident)["status"].upper() in CLOSED:
            return 0
        self.require_admin(org, auth["actor"])
        row, _ = self._proposal(org, incident, auth["proposal_id"])
        records = OrchestrationStore(self.db)
        existing = records.list_evidence(org, incident_id=incident)
        root = next(
            (
                t
                for t in records.list_tasks(org, incident_id=incident)
                if t.role == "main_orchestrator"
            ),
            None,
        )
        if root is None:
            return 0
        seen = {
            r.content.get("source_event_id")
            for r in existing
            if r.source == "source.wazuh_import" and isinstance(r.content, dict)
        }
        count = 0
        with self.db.transaction():
            current = self.db.fetchone(
                "SELECT revoked_at FROM live_response_authorizations WHERE authorization_id=?",
                (auth["authorization_id"],),
            )
            if not current or current["revoked_at"]:
                return 0
            for observation in collection.observations:
                if (
                    observation.source_id != "wazuh-indexer"
                    or observation.source_event_id in seen
                    or not isinstance(observation.data, dict)
                ):
                    continue
                alert = observation.data.get("alert", {})
                if not isinstance(alert, dict):
                    continue
                if (
                    alert.get("agent", {}).get("id"),
                    alert.get("agent", {}).get("ip"),
                    alert.get("data", {}).get("srcip"),
                ) != ("001", "10.77.0.20", "10.77.0.10"):
                    continue
                if not {"sshd", "authentication_failed"} <= set(
                    alert.get("rule", {}).get("groups", [])
                ):
                    continue
                try:
                    stamp = datetime.fromisoformat(alert["timestamp"])
                except (ValueError, KeyError, TypeError):
                    continue
                if (
                    stamp.tzinfo is None
                    or not datetime.fromisoformat(row["created_at"])
                    <= stamp
                    <= self.clock()
                    or (self.clock() - stamp).total_seconds() > 120
                ):
                    continue
                evidence = records.create_evidence(
                    org,
                    root.task_id,
                    "source.wazuh_import",
                    observation.source_timestamp,
                    content=observation.model_dump(mode="json"),
                )
                self.record_source(org, incident, evidence.evidence_id)
                seen.add(observation.source_event_id)
                count += 1
            if count:
                self._event(
                    org,
                    incident,
                    auth["proposal_id"],
                    "evidence_linked",
                    f"{count} fresh matching authenticated source records linked to this incident",
                )
        return count

    def revise(
        self,
        org: str,
        incident: str,
        proposal: str,
        actor: str,
        expected: str,
        duration: int,
    ) -> dict[str, Any]:
        self.require_admin(org, actor)
        if not 30 <= duration <= 120:
            raise ValueError("Duration must be between 30 and 120 seconds")
        with self.db.transaction():
            _, payload = self._proposal(org, incident, proposal, expected)
            if payload["action"] != "response.wazuh_ip_block":
                raise ResponseConflictError(
                    "Only supported response parameters may be revised"
                )
            payload = {
                **payload,
                "duration_seconds": duration,
                "origin": "human",
                "creator_id": actor,
                "parent_proposal_id": proposal,
            }
            new_id = str(uuid4())
            self.db.execute(
                "INSERT INTO live_response_proposals VALUES(?,?,?,?,?,?)",
                (
                    new_id,
                    org,
                    incident,
                    digest(payload),
                    canonical(payload),
                    self.clock().isoformat(),
                ),
            )
            self.db.execute(
                "UPDATE live_response_authorizations SET revoked_at=? WHERE org_id=? AND incident_id=? AND revoked_at IS NULL",
                (self.clock().isoformat(), org, incident),
            )
            self._event(
                org,
                incident,
                proposal,
                "superseded",
                "Parameters revised; prior authorizations revoked",
            )
            self._event(
                org,
                incident,
                new_id,
                "recommended",
                "Human-authored revision; a different admin must approve",
            )
        return self.inspect(org, incident)

    def _proposal(
        self, org: str, incident: str, proposal: str | None, expected: str | None = None
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.db.fetchone(
            "SELECT * FROM live_response_proposals WHERE org_id=? AND incident_id=? AND proposal_id=?",
            (org, incident, proposal),
        )
        if not row:
            raise LookupError("Proposal not found")
        payload = json.loads(row["payload"])
        if digest(payload) != row["digest"] or (expected and expected != row["digest"]):
            raise ResponseConflictError("Proposal changed; review the current revision")
        return row, payload

    def capability(  # noqa: PLR0911 -- explicit capability reasons
        self, org: str, incident: str, row: dict[str, Any], payload: dict[str, Any]
    ) -> str:
        if self.db.fetchone(
            "SELECT 1 FROM live_response_events WHERE proposal_id=? AND state='superseded'",
            (row["proposal_id"],),
        ):
            return "Superseded"
        if (
            payload["action"] not in CAPABILITIES
            or not CAPABILITIES[payload["action"]].executable
        ):
            return "Unsupported action"
        if self._incident(org, incident)["status"].upper() in CLOSED:
            return "Incident closed"
        if self.clock() > datetime.fromisoformat(row["created_at"]) + timedelta(
            minutes=30
        ):
            return "Needs fresh evidence"
        if len(payload["timestamps"]) < 3 or any(
            not 0 <= (self.clock() - datetime.fromisoformat(t)).total_seconds() <= 120
            for t in payload["timestamps"].values()
        ):
            return "Needs fresh evidence"
        records = {
            r.evidence_id: r
            for r in OrchestrationStore(self.db).list_evidence(
                org, incident_id=incident
            )
        }
        if any(
            e["id"] not in records or digest(records[e["id"]].content) != e["hash"]
            for e in payload["evidence"]
        ):
            return "Needs fresh evidence"
        if any(
            not self.db.fetchone(
                "SELECT 1 FROM live_response_source_receipts WHERE org_id=? AND incident_id=? AND evidence_id=? AND content_hash=?",
                (org, incident, e["id"], e["hash"]),
            )
            for e in payload["evidence"]
        ):
            return "Needs fresh evidence"
        if not self.ready(org):
            return "Connector unavailable"
        return "Ready"

    def scope(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            key: payload[key]
            for key in (
                "action",
                "agent_id",
                "source_ip",
                "target_ip",
                "duration_seconds",
                "cooldown_seconds",
                "max_actions",
                "threshold",
            )
        }

    def decide(
        self,
        org: str,
        incident: str,
        proposal: str | None,
        actor: str,
        expected: str | None,
        decision: str,
        note: str = "",
    ) -> dict[str, Any]:
        self.require_admin(org, actor)
        if decision not in {"approve", "autonomy", "reject", "defer"}:
            raise ValueError("Invalid decision")
        if decision == "reject" and not note.strip():
            raise ValueError("Rejection reason required")
        with self.db.transaction():
            row, payload = self._proposal(org, incident, proposal, expected)
            prior = self.db.fetchone(
                "SELECT * FROM live_response_decisions WHERE org_id=? AND proposal_id=? AND decision!='defer' ORDER BY id DESC LIMIT 1",
                (org, proposal),
            )
            if prior:
                if prior["decision"] == decision and prior["actor"] == actor:
                    return self.inspect(org, incident)
                raise ResponseConflictError("Proposal already decided")
            if decision in {"approve", "autonomy"}:
                if self.capability(org, incident, row, payload) != "Ready":
                    raise ResponseConflictError(
                        "Response is not ready; refresh evidence and connector state"
                    )
                if payload["origin"] == "human" and payload["creator_id"] == actor:
                    raise PermissionError("Human authors cannot self-approve")
                active = self.db.fetchone(
                    "SELECT 1 FROM live_response_authorizations WHERE org_id=? AND incident_id=? AND revoked_at IS NULL AND expires_at>?",
                    (org, incident, self.clock().isoformat()),
                )
                if active:
                    raise ResponseConflictError(
                        "Stop the existing authorization before changing scope"
                    )
                ttl = (
                    timedelta(minutes=30)
                    if decision == "autonomy"
                    else timedelta(minutes=5)
                )
                self.db.execute(
                    "INSERT INTO live_response_authorizations VALUES(?,?,?,?,?,?,?,?,NULL)",
                    (
                        str(uuid4()),
                        org,
                        incident,
                        proposal,
                        actor,
                        decision,
                        canonical(self.scope(payload)),
                        (self.clock() + ttl).isoformat(),
                    ),
                )
            self.db.execute(
                "INSERT INTO live_response_decisions(org_id,proposal_id,actor,decision,note,created_at) VALUES(?,?,?,?,?,?)",
                (org, proposal, actor, decision, note[:2000], self.clock().isoformat()),
            )
            self._event(
                org,
                incident,
                proposal,
                decision,
                "Operator decision recorded: " + note[:2000],
            )
        return self.inspect(org, incident)

    def stop(self, org: str, incident: str, actor: str) -> dict[str, Any]:
        self.require_admin(org, actor)
        self._incident(org, incident)
        with self.db.transaction():
            self.db.execute(
                "UPDATE live_response_authorizations SET revoked_at=? WHERE org_id=? AND incident_id=? AND revoked_at IS NULL",
                (self.clock().isoformat(), org, incident),
            )
            self._event(
                org,
                incident,
                None,
                "revoked",
                "Autonomy/queued authorization stopped; existing effects still expire and are reconciled",
            )
        return self.inspect(org, incident)

    def inspect(self, org: str, incident: str) -> dict[str, Any]:
        item = self._incident(org, incident)
        if item["status"].upper() in CLOSED:
            self.db.execute(
                "UPDATE live_response_authorizations SET revoked_at=? WHERE org_id=? AND incident_id=? AND revoked_at IS NULL",
                (self.clock().isoformat(), org, incident),
            )
        proposals = []
        for row in self.db.fetchall(
            "SELECT * FROM live_response_proposals WHERE org_id=? AND incident_id=? ORDER BY created_at DESC,rowid DESC",
            (org, incident),
        ):
            _, payload = self._proposal(org, incident, row["proposal_id"])
            decision = self.db.fetchone(
                "SELECT decision,note,actor,created_at FROM live_response_decisions WHERE org_id=? AND proposal_id=? ORDER BY id DESC LIMIT 1",
                (org, row["proposal_id"]),
            )
            proposals.append(
                {
                    "proposal_id": row["proposal_id"],
                    "digest": row["digest"],
                    "created_at": row["created_at"],
                    **payload,
                    "capability": self.capability(org, incident, row, payload),
                    "decision": decision,
                }
            )
        return {
            "incident_id": incident,
            "operation_id": next(
                (e["task_id"] for p in proposals for e in p["evidence"]), None
            ),
            "proposals": proposals,
            "authorizations": self.db.fetchall(
                "SELECT authorization_id,mode,scope,expires_at,revoked_at FROM live_response_authorizations WHERE org_id=? AND incident_id=?",
                (org, incident),
            ),
            "intents": self.db.fetchall(
                "SELECT intent_id,proposal_id,state,created_at,updated_at FROM live_response_intents WHERE org_id=? AND incident_id=?",
                (org, incident),
            ),
            "events": self.db.fetchall(
                "SELECT * FROM live_response_events WHERE org_id=? AND incident_id=? ORDER BY id",
                (org, incident),
            ),
            "observations": self.db.fetchall(
                "SELECT o.* FROM live_response_observations o JOIN live_response_intents i ON i.intent_id=o.intent_id WHERE i.org_id=? AND i.incident_id=? ORDER BY o.id",
                (org, incident),
            ),
            "fixture_only": False,
        }

    async def observe(
        self,
        observer: Callable[[str, dict[str, Any]], Awaitable[bool]],
        phase: str,
        details: dict[str, Any],
    ) -> bool:
        verified = await observer(phase, details)
        self.db.execute(
            "INSERT INTO live_response_observations(intent_id,phase,verified,observed_at) VALUES(?,?,?,?)",
            (details.get("intent_id"), phase, int(verified), self.clock().isoformat()),
        )
        return verified

    def _state(self, intent: str | None, state: str, detail: str) -> None:
        with self.db.transaction():
            row = self.db.fetchone(
                "SELECT * FROM live_response_intents WHERE intent_id=?", (intent,)
            )
            if not row or row["state"] in TERMINAL:
                return
            self.db.execute(
                "UPDATE live_response_intents SET state=?,updated_at=? WHERE intent_id=?",
                (state, self.clock().isoformat(), intent),
            )
            self._event(
                row["org_id"],
                row["incident_id"],
                row["proposal_id"],
                state,
                detail,
                intent,
            )

    def _reserve(  # noqa: PLR0911 -- ordered fail-closed gates
        self,
        org: str,
        incident: str,
        auth: dict[str, Any],
        row: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        with self.db.transaction():
            self.require_admin(org, auth["actor"])
            current = self.db.fetchone(
                "SELECT * FROM live_response_authorizations WHERE authorization_id=?",
                (auth["authorization_id"],),
            )
            if (
                not current
                or current["revoked_at"]
                or datetime.fromisoformat(current["expires_at"]) <= self.clock()
            ):
                return None
            if self.capability(org, incident, row, payload) != "Ready" or self.scope(
                payload
            ) != json.loads(auth["scope"]):
                return None
            if auth["mode"] == "approve" and auth["proposal_id"] != row["proposal_id"]:
                return None
            if self.db.fetchone(
                "SELECT 1 FROM live_response_intents WHERE proposal_id=?",
                (row["proposal_id"],),
            ):
                return None
            decision = self.db.fetchone(
                "SELECT decision FROM live_response_decisions WHERE proposal_id=? ORDER BY id DESC LIMIT 1",
                (row["proposal_id"],),
            )
            if decision and decision["decision"] in {"reject", "defer"}:
                return None
            history = self.db.fetchall(
                "SELECT * FROM live_response_intents WHERE org_id=?", (org,)
            )
            if any(r["state"] not in TERMINAL for r in history):
                return None
            if (
                sum(r["authorization_id"] == auth["authorization_id"] for r in history)
                >= payload["max_actions"]
            ):
                return None
            if any(
                (self.clock() - datetime.fromisoformat(r["created_at"])).total_seconds()
                < 300
                for r in history
            ):
                return None
            seen = {e for r in history for e in json.loads(r["payload"])["event_ids"]}
            if seen.intersection(payload["event_ids"]):
                return None
            intent = str(uuid4())
            details = {**payload, "intent_id": intent, "proposal_digest": row["digest"]}
            self.db.execute(
                "INSERT INTO live_response_intents VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    intent,
                    org,
                    incident,
                    row["proposal_id"],
                    auth["authorization_id"],
                    row["digest"],
                    canonical(details),
                    "in_flight",
                    self.clock().isoformat(),
                    self.clock().isoformat(),
                ),
            )
            self._event(
                org,
                incident,
                row["proposal_id"],
                "in_flight",
                "Durable dispatch intent recorded before provider I/O",
                intent,
            )
            return details

    def autonomous_proposal(self, org: str, incident: str, auth: dict[str, Any]) -> str:
        original_row, original_payload = self._proposal(
            org, incident, auth["proposal_id"]
        )
        if (
            not self.db.fetchone(
                "SELECT 1 FROM live_response_intents WHERE proposal_id=?",
                (auth["proposal_id"],),
            )
            and self.capability(org, incident, original_row, original_payload)
            == "Ready"
        ):
            return auth["proposal_id"]
        candidate = self.refresh(org, incident)
        _, payload = self._proposal(org, incident, candidate)
        scope = json.loads(auth["scope"])
        if self.scope(payload) == scope:
            return candidate
        # Only a duration already reviewed in this authorization may carry forward.
        if any(
            payload.get(k) != v for k, v in scope.items() if k != "duration_seconds"
        ):
            return candidate
        payload = {
            **payload,
            "duration_seconds": scope["duration_seconds"],
            "origin": "system",
            "creator_id": None,
        }
        fingerprint = digest(payload)
        with self.db.transaction():
            prior = self.db.fetchone(
                "SELECT proposal_id FROM live_response_proposals WHERE org_id=? AND incident_id=? AND digest=?",
                (org, incident, fingerprint),
            )
            if prior:
                return prior["proposal_id"]
            proposal = str(uuid4())
            self.db.execute(
                "INSERT INTO live_response_proposals VALUES(?,?,?,?,?,?)",
                (
                    proposal,
                    org,
                    incident,
                    fingerprint,
                    canonical(payload),
                    self.clock().isoformat(),
                ),
            )
            self._event(
                org,
                incident,
                proposal,
                "recommended",
                "Fresh system proposal retains the exact incident-authorized scope",
            )
            return proposal

    async def tick(  # noqa: C901, PLR0912 -- response lifecycle
        self,
        org: str,
        transport: WazuhResponseTransport,
        observer: Callable[[str, dict[str, Any]], Awaitable[bool]],
        *,
        available: bool = True,
    ) -> None:
        if available:
            self.takeover(org)
        else:
            self.db.execute("DELETE FROM live_response_runtime WHERE org_id=?", (org,))
        # Recovery is observed even after revocation/closure; no provider retry.
        for row in self.db.fetchall(
            "SELECT * FROM live_response_intents WHERE org_id=? AND state NOT IN ('recovered','recovered_unverified','denied','unavailable','cancelled')",
            (org,),
        ):
            details = json.loads(row["payload"])
            if self.clock() >= datetime.fromisoformat(row["created_at"]) + timedelta(
                seconds=details["duration_seconds"] + 15
            ) and await self.observe(observer, "recovered", details):
                verified = self.db.fetchone(
                    "SELECT 1 FROM live_response_events WHERE intent_id=? AND state='verified_blocked'",
                    (row["intent_id"],),
                )
                self._state(
                    row["intent_id"],
                    "recovered" if verified else "recovered_unverified",
                    "Independent source, management and owned-set recovery confirmed",
                )
        if not available:
            return
        auths = self.db.fetchall(
            "SELECT * FROM live_response_authorizations WHERE org_id=? AND revoked_at IS NULL AND expires_at>?",
            (org, self.clock().isoformat()),
        )
        for auth in auths:
            incident = auth["incident_id"]
            if self._incident(org, incident)["status"].upper() in CLOSED:
                self.db.execute(
                    "UPDATE live_response_authorizations SET revoked_at=? WHERE authorization_id=?",
                    (self.clock().isoformat(), auth["authorization_id"]),
                )
                continue
            proposal = (
                auth["proposal_id"]
                if auth["mode"] == "approve"
                else self.autonomous_proposal(org, incident, auth)
            )
            row, payload = self._proposal(org, incident, proposal)
            if self.capability(org, incident, row, payload) != "Ready":
                continue
            if not await self.observe(observer, "baseline", {}):
                continue
            try:
                details = self._reserve(org, incident, auth, row, payload)
            except PermissionError:
                continue
            if not details:
                continue
            try:
                result = await transport.dispatch(
                    WazuhBlockRequest(
                        org_id=org,
                        intent_id=details["intent_id"],
                        proposal_digest=row["digest"],
                        agent_id="001",
                        source_ip=IPv4Address("10.77.0.10"),
                        duration_seconds=details["duration_seconds"],
                    )
                )
                self._state(
                    details["intent_id"],
                    result.status,
                    "Provider result recorded; acknowledgement is not verification",
                )
                if result.status == "acknowledged":
                    for _ in range(5):
                        if await self.observe(observer, "blocked", details):
                            self._state(
                                details["intent_id"],
                                "verified_blocked",
                                "Independent source denied, management healthy, owned set contains source",
                            )
                            break
                        await asyncio.sleep(1)
                    else:
                        self._state(
                            details["intent_id"],
                            "unknown",
                            "Effect could not be independently confirmed; reconciliation required",
                        )
            except BaseException:
                self._state(
                    details["intent_id"],
                    "unknown",
                    "Interrupted or ambiguous dispatch; reconciliation required",
                )
                raise
