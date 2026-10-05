# pyright: reportAny=false, reportExplicitAny=false
"""Durable fixture response records, with immutable plans and approvals."""

from __future__ import annotations

import hashlib
import json
from typing import Any, final

from terminus.storage.db import Database


class ResponseDeniedError(ValueError):
    """Current authorization or an exact binding does not permit the request."""


class ResponseConflictError(ValueError):
    """Immutable input or a lifecycle state conflicts with an existing record."""


class ResponseNotFoundError(LookupError):
    """Missing and foreign-tenant IDs deliberately have the same result."""


def canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


@final
class ResponseStore:
    def __init__(self, db: Database) -> None:
        self.db = db
        with db.transaction() as conn:
            for statement in _SCHEMA:
                _ = conn.execute(statement)

    def proposal(self, org_id: str, proposal_id: str) -> dict[str, Any]:
        row = self.db.fetchone(
            "SELECT * FROM response_proposals WHERE org_id=? AND proposal_id=?",
            (org_id, proposal_id),
        )
        if row is None:
            raise ResponseNotFoundError("Response record not found")
        return row

    def intent(self, org_id: str, intent_id: str) -> dict[str, Any]:
        row = self.db.fetchone(
            "SELECT * FROM response_intents WHERE org_id=? AND intent_id=?",
            (org_id, intent_id),
        )
        if row is None:
            raise ResponseNotFoundError("Response record not found")
        return row


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS response_policies (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, version INTEGER NOT NULL,
        policy_version TEXT NOT NULL, payload_json TEXT NOT NULL,
        PRIMARY KEY(org_id,incident_id,version))""",
    """CREATE TABLE IF NOT EXISTS response_active_policies (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, version INTEGER NOT NULL,
        PRIMARY KEY(org_id,incident_id))""",
    """CREATE TABLE IF NOT EXISTS response_targets (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, policy_version TEXT NOT NULL,
        target_id TEXT NOT NULL, payload_json TEXT NOT NULL,
        PRIMARY KEY(org_id,incident_id,policy_version,target_id))""",
    """CREATE TABLE IF NOT EXISTS response_proposals (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, proposal_id TEXT NOT NULL,
        creator_id TEXT NOT NULL, digest TEXT NOT NULL, payload_json TEXT NOT NULL,
        evidence_hashes_json TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(org_id,proposal_id))""",
    """CREATE TABLE IF NOT EXISTS response_decisions (
        org_id TEXT NOT NULL, proposal_id TEXT NOT NULL, actor_id TEXT NOT NULL,
        decision TEXT NOT NULL, binding_json TEXT, created_at TEXT NOT NULL,
        PRIMARY KEY(org_id,proposal_id))""",
    """CREATE TABLE IF NOT EXISTS response_intents (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, intent_id TEXT NOT NULL,
        proposal_id TEXT NOT NULL, proposal_digest TEXT NOT NULL,
        idempotency_key TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL,
        dispatch_run_id TEXT, dispatched_at TEXT, verification_json TEXT,
        detail TEXT, PRIMARY KEY(org_id,intent_id),
        UNIQUE(org_id,proposal_id), UNIQUE(org_id,idempotency_key))""",
    """CREATE TABLE IF NOT EXISTS response_fixture_receipts (
        org_id TEXT NOT NULL, intent_id TEXT NOT NULL, proposal_digest TEXT NOT NULL,
        resource_id TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL,
        PRIMARY KEY(org_id,intent_id), UNIQUE(org_id,resource_id))""",
    """CREATE TABLE IF NOT EXISTS response_owned_resources (
        org_id TEXT NOT NULL, incident_id TEXT NOT NULL, resource_id TEXT NOT NULL,
        intent_id TEXT NOT NULL, proposal_digest TEXT NOT NULL, expires_at TEXT NOT NULL,
        state TEXT NOT NULL, PRIMARY KEY(org_id,resource_id), UNIQUE(org_id,intent_id))""",
    """CREATE TABLE IF NOT EXISTS response_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT NOT NULL,
        proposal_id TEXT NOT NULL, intent_id TEXT, state TEXT NOT NULL,
        timestamp TEXT NOT NULL, detail TEXT NOT NULL)""",
    # The public service never edits these records. SQLite also rejects accidental
    # direct writes that would change an approved scope or evidence snapshot.
    """CREATE TRIGGER IF NOT EXISTS response_proposals_immutable_update
        BEFORE UPDATE ON response_proposals BEGIN SELECT RAISE(ABORT,'immutable response proposal'); END""",
    """CREATE TRIGGER IF NOT EXISTS response_proposals_immutable_delete
        BEFORE DELETE ON response_proposals BEGIN SELECT RAISE(ABORT,'immutable response proposal'); END""",
    """CREATE TRIGGER IF NOT EXISTS response_decisions_immutable_update
        BEFORE UPDATE ON response_decisions BEGIN SELECT RAISE(ABORT,'immutable response decision'); END""",
    """CREATE TRIGGER IF NOT EXISTS response_decisions_immutable_delete
        BEFORE DELETE ON response_decisions BEGIN SELECT RAISE(ABORT,'immutable response decision'); END""",
    """CREATE TRIGGER IF NOT EXISTS response_intents_immutable_identity
        BEFORE UPDATE OF org_id,incident_id,intent_id,proposal_id,proposal_digest,idempotency_key,created_at
        ON response_intents BEGIN SELECT RAISE(ABORT,'immutable response intent identity'); END""",
)
