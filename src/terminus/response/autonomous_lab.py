"""Opt-in autonomous Scenario A controller. Fixed lab scope; no model-selected targets."""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any, Literal
from uuid import uuid4

from pydantic import Field

from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.response.storage import canonical, digest
from terminus.response.wazuh_transport import WazuhBlockRequest, WazuhResponseTransport
from terminus.storage.db import Database
from terminus.toolkit.lab_import import import_authentication_incident
from terminus.toolkit.models import Contract, Id
from terminus.toolkit.sources import ReadCollection


class LabAutonomousPolicy(Contract):
    org_id: Id
    actor_id: Id
    version: Literal[1] = 1
    agent_id: Literal["001"] = "001"
    source_ip: Literal["10.77.0.10"] = "10.77.0.10"
    target_ip: Literal["10.77.0.20"] = "10.77.0.20"
    threshold: int = Field(default=3, ge=3, le=20)
    duration_seconds: int = Field(default=60, ge=30, le=120)
    max_actions: int = Field(default=3, ge=1, le=5)
    cooldown_seconds: int = Field(default=300, ge=300, le=3600)
    enabled_until: datetime


# Observer executes independent, fixed checks, never interprets acknowledgement as effect.
Observer = Callable[[str, dict[str, Any]], Awaitable[bool]]


class AutonomousLabController:
    def __init__(self, db: Database, transport: WazuhResponseTransport, observer: Observer,
                 *, clock: Callable[[], datetime] | None = None) -> None:
        self.db, self.transport, self.observer = db, transport, observer
        self.clock = clock or (lambda: datetime.now(UTC))
        with db.transaction() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS autonomous_lab_policy (org_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, digest TEXT NOT NULL, payload TEXT NOT NULL, enabled_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS autonomous_lab_intents (intent_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, incident_id TEXT NOT NULL, policy_digest TEXT NOT NULL, proposal_digest TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS autonomous_lab_policy_history (digest TEXT PRIMARY KEY, payload TEXT NOT NULL, actor_id TEXT NOT NULL, created_at TEXT NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS autonomous_lab_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, intent_id TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL)")

    def _admin(self, policy: LabAutonomousPolicy) -> None:
        if SqliteMembershipStore(self.db).role_of(OrgId(policy.org_id), UserId(policy.actor_id)) != OrganizationRole.ADMIN:
            raise ValueError("Current organization administrator required")

    def enable(self, policy: LabAutonomousPolicy) -> None:
        now = self.clock()
        if policy.enabled_until.tzinfo is None or not now < policy.enabled_until <= now + timedelta(hours=1):
            raise ValueError("Policy expiry must be within one hour")
        with self.db.transaction() as conn:
            self._admin(policy)
            if conn.execute("SELECT 1 FROM autonomous_lab_intents WHERE org_id=? AND state NOT IN ('recovered','recovered_unverified','unavailable','denied')", (policy.org_id,)).fetchone():
                raise ValueError("Unresolved response requires reconciliation before re-enabling")
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='live_response_control'").fetchone() and conn.execute("SELECT 1 FROM live_response_control WHERE mode='console'").fetchone():
                raise ValueError("Console response worker owns dispatch; standalone controller disabled")
            payload = policy.model_dump(mode="json")
            conn.execute("INSERT OR IGNORE INTO autonomous_lab_policy_history VALUES(?,?,?,?)", (digest(payload), canonical(payload), policy.actor_id, now.isoformat()))
            conn.execute("INSERT INTO autonomous_lab_policy VALUES(?,?,?,?,?) ON CONFLICT(org_id) DO UPDATE SET actor_id=excluded.actor_id,digest=excluded.digest,payload=excluded.payload,enabled_at=excluded.enabled_at", (policy.org_id, policy.actor_id, digest(payload), canonical(payload), now.isoformat()))

    def _policy(self, org: str) -> tuple[LabAutonomousPolicy, str, datetime]:
        row = self.db.fetchone("SELECT * FROM autonomous_lab_policy WHERE org_id=?", (org,))
        if row is None:
            raise ValueError("Autonomous policy not enabled")
        policy = LabAutonomousPolicy.model_validate_json(row["payload"])
        self._admin(policy)
        if digest(policy.model_dump(mode="json")) != row["digest"] or self.clock() >= policy.enabled_until:
            raise ValueError("Autonomous policy expired or altered")
        return policy, row["digest"], datetime.fromisoformat(row["enabled_at"])

    def _state(self, intent: str, state: str) -> None:
        now = self.clock().isoformat()
        with self.db.transaction() as conn:
            current = conn.execute("SELECT state FROM autonomous_lab_intents WHERE intent_id=?", (intent,)).fetchone()
            if current is None:
                raise ValueError("Action intent is missing")
            if current["state"] in {"recovered", "recovered_unverified", "unavailable", "denied"}:
                return  # Reconciliation fences late worker updates.
            conn.execute("UPDATE autonomous_lab_intents SET state=?,updated_at=? WHERE intent_id=?", (state, now, intent))
            conn.execute("INSERT INTO autonomous_lab_events(intent_id,state,created_at) VALUES(?,?,?)", (intent, state, now))

    @staticmethod
    def _select(collection: ReadCollection, enabled_at: datetime, now: datetime) -> dict:
        unique = {}
        for item in collection.observations:
            if item.source_id != "wazuh-indexer" or not enabled_at <= item.source_timestamp <= now or now - item.source_timestamp > timedelta(seconds=120):
                continue
            data = item.data
            alert = data.get("alert", {}) if isinstance(data, dict) else {}
            agent, source, rule = (alert.get(key, {}) for key in ("agent", "data", "rule"))
            if not all(isinstance(value, dict) for value in (agent, source, rule)):
                continue
            if (agent.get("id"), agent.get("ip"), source.get("srcip")) != ("001", "10.77.0.20", "10.77.0.10"):
                continue
            groups = rule.get("groups", [])
            if isinstance(groups, list) and "sshd" in groups and "authentication_failed" in groups:
                unique[item.source_event_id] = item
        return unique

    @staticmethod
    def _hold(policy: LabAutonomousPolicy, rows: list, now: datetime, unique: dict) -> str | None:
        if any(row["state"] not in {"recovered", "recovered_unverified", "unavailable", "denied"} for row in rows):
            return "reconciliation_required"
        if len(rows) >= policy.max_actions:
            return "quota_exhausted"
        if any(now - datetime.fromisoformat(row["created_at"]) < timedelta(seconds=policy.cooldown_seconds) for row in rows):
            return "cooldown"
        seen = {event for row in rows for event in json.loads(row["payload"])["source_event_ids"]}
        return "duplicate_events" if seen.intersection(unique) else None

    async def process(self, org: str, collection: ReadCollection) -> str:  # noqa: C901, PLR0911, PLR0912 -- ordered fail-closed dispatch gates
        policy, policy_digest, enabled_at = self._policy(org)
        now = self.clock()
        if collection.status != "ok" or collection.coverage != "complete" or collection.gaps or collection.truncated:
            return "incomplete_collection"
        unique = self._select(collection, enabled_at, now)
        if len(unique) < policy.threshold:
            return "below_threshold"
        prior = self.db.fetchall("SELECT * FROM autonomous_lab_intents WHERE org_id=?", (org,))
        if hold := self._hold(policy, prior, now, unique):
            return hold
        # Live baseline is a prerequisite, not a substituted fixture result.
        if not await self.observer("baseline", {}):
            return "baseline_unavailable"
        with self.db.transaction() as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='live_response_control'").fetchone() and conn.execute("SELECT 1 FROM live_response_control WHERE mode='console'").fetchone():
                return "console_dispatch_owned"
            current, current_digest, current_enabled = self._policy(org)
            now = self.clock()
            unique = self._select(collection, current_enabled, now)
            if len(unique) < current.threshold:
                return "stale_after_baseline"
            if current_digest != policy_digest:
                return "policy_changed"
            rows = conn.execute("SELECT * FROM autonomous_lab_intents WHERE org_id=?", (org,)).fetchall()
            if hold := self._hold(current, rows, now, unique):
                return hold
            selected = ReadCollection(status="ok", coverage="complete", observations=tuple(unique.values()))
            incident = import_authentication_incident(self.db, org_id=org, actor=current.actor_id, agent_id=current.agent_id, collection=selected)
            intent = str(uuid4())
            proposal = {"org_id": org, "incident_id": incident, "policy_digest": policy_digest,
                        "agent_id": current.agent_id, "source_ip": current.source_ip, "target_ip": current.target_ip,
                        "duration_seconds": current.duration_seconds, "source_event_ids": sorted(unique),
                        "undo": "owned_resource_only", "verification": "independent_source_management_and_owned_table"}
            proposal_digest = digest(proposal)
            conn.execute("INSERT INTO autonomous_lab_intents VALUES(?,?,?,?,?,?,?,?,?)", (intent, org, incident, policy_digest, proposal_digest, canonical(proposal), "in_flight", now.isoformat(), now.isoformat()))
            conn.execute("INSERT INTO autonomous_lab_events(intent_id,state,created_at) VALUES(?,?,?)", (intent, "in_flight", now.isoformat()))
        request = WazuhBlockRequest(org_id=org, intent_id=intent, proposal_digest=proposal_digest,
                                   agent_id=policy.agent_id, source_ip=IPv4Address(policy.source_ip), duration_seconds=policy.duration_seconds)
        try:
            outcome = await self.transport.dispatch(request)
        except BaseException:
            self._state(intent, "unknown")
            raise
        self._state(intent, outcome.status)
        if outcome.status != "acknowledged":
            return outcome.status
        details = {**proposal, "intent_id": intent, "proposal_digest": proposal_digest}
        for _ in range(5):
            if await self.observer("blocked", details):
                self._state(intent, "verified_blocked")
                break
            await asyncio.sleep(1)
        else:
            self._state(intent, "unknown")
            return "unknown"
        await asyncio.sleep(policy.duration_seconds + 5)
        if await self.observer("recovered", details):
            self._state(intent, "recovered")
            return "recovered"
        self._state(intent, "unknown")
        return "unknown"



async def reconcile_lab_actions(
    db: Database,
    org_id: str,
    actor_id: str,
    observer: Observer,
    *,
    clock: Callable[[], datetime] | None = None,
) -> list[dict[str, str]]:
    """Observe expired effects after interruption. Never sends or renews an action."""
    if SqliteMembershipStore(db).role_of(OrgId(org_id), UserId(actor_id)) != OrganizationRole.ADMIN:
        raise ValueError("Current organization administrator required")
    now = (clock or (lambda: datetime.now(UTC)))()
    rows = db.fetchall("SELECT * FROM autonomous_lab_intents WHERE org_id=? AND state NOT IN ('recovered','recovered_unverified','unavailable','denied')", (org_id,))
    results = []
    for row in rows:
        proposal = json.loads(row["payload"])
        snapshot = db.fetchone("SELECT payload FROM autonomous_lab_policy_history WHERE digest=?", (row["policy_digest"],))
        if snapshot is None or digest(proposal) != row["proposal_digest"]:
            raise ValueError("Action integrity could not be established")
        policy = LabAutonomousPolicy.model_validate_json(snapshot["payload"])
        if digest(policy.model_dump(mode="json")) != row["policy_digest"] or policy.org_id != org_id:
            raise ValueError("Policy snapshot integrity could not be established")
        expected = (policy.agent_id, policy.source_ip, policy.target_ip, policy.duration_seconds, row["policy_digest"], row["incident_id"], org_id)
        actual = tuple(proposal.get(key) for key in ("agent_id", "source_ip", "target_ip", "duration_seconds", "policy_digest", "incident_id", "org_id"))
        if actual != expected:
            raise ValueError("Action does not bind the authorized scope")
        intent_id = row["intent_id"]
        if now < datetime.fromisoformat(row["created_at"]) + timedelta(seconds=policy.duration_seconds + 15):
            results.append({"intent_id": intent_id, "state": "waiting_for_expiry"})
            continue
        details = {**proposal, "intent_id": intent_id, "proposal_digest": row["proposal_digest"]}
        if not await observer("recovered", details):
            results.append({"intent_id": intent_id, "state": "unresolved"})
            continue
        with db.transaction() as conn:
            if SqliteMembershipStore(db).role_of(OrgId(org_id), UserId(actor_id)) != OrganizationRole.ADMIN:
                raise ValueError("Current organization administrator required")
            verified = conn.execute("SELECT 1 FROM autonomous_lab_events WHERE intent_id=? AND state='verified_blocked'", (intent_id,)).fetchone()
            state = "recovered" if verified else "recovered_unverified"
            changed = conn.execute("UPDATE autonomous_lab_intents SET state=?,updated_at=? WHERE intent_id=? AND org_id=? AND state=?", (state, now.isoformat(), intent_id, org_id, row["state"])).rowcount
            if changed:
                conn.execute("INSERT INTO autonomous_lab_events(intent_id,state,created_at) VALUES(?,?,?)", (intent_id, state, now.isoformat()))
                results.append({"intent_id": intent_id, "state": state})
    return results
