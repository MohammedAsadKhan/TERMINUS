"""Tenant-scoped SQLite persistence, with no scheduling or external execution."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from typing import TypeVar, cast

from pydantic import JsonValue, TypeAdapter

from terminus.orchestration.models import (
    ActionAttempt,
    ActionAttemptEvent,
    ActionStatus,
    AgentRun,
    DurableRecord,
    EvidenceRecord,
    HelpRequest,
    HelpStatus,
    Identifier,
    RunStatus,
    Task,
    TaskStatus,
    utc_now,
)
from terminus.storage.db import Database

Record = TypeVar("Record", bound=DurableRecord)
_IDENTIFIER: TypeAdapter[str] = TypeAdapter(Identifier)
_TABLES: dict[type[DurableRecord], tuple[str, str]] = {
    Task: ("orchestration_tasks", "task_id"),
    AgentRun: ("orchestration_agent_runs", "run_id"),
    EvidenceRecord: ("orchestration_evidence", "evidence_id"),
    HelpRequest: ("orchestration_help_requests", "help_request_id"),
    ActionAttempt: ("orchestration_action_attempts", "attempt_id"),
    ActionAttemptEvent: ("orchestration_action_events", "event_id"),
}
_TRANSITIONS: dict[type[DurableRecord], dict[str, set[str]]] = {
    Task: {
        "queued": {"running", "cancelled"},
        "running": {"waiting", "completed", "failed", "cancelled"},
        "waiting": {"running", "failed", "cancelled"},
    },
    AgentRun: {
        "queued": {"running", "cancelled"},
        "running": {"completed", "failed", "cancelled"},
    },
    HelpRequest: {
        "open": {"assigned", "resolved", "cancelled"},
        "assigned": {"resolved", "cancelled"},
    },
    ActionAttempt: {
        "proposed": {"approved", "rejected"},
        "approved": {"dispatched", "rejected"},
        "dispatched": {"acknowledged", "failed", "unknown"},
        "acknowledged": {"verified", "failed", "unknown"},
        "unknown": {"acknowledged", "failed"},
    },
}


class OrchestrationNotFoundError(LookupError):
    """Missing and foreign-tenant IDs deliberately return the same error."""


class OrchestrationConflictError(ValueError):
    """An idempotency collision or stale compare-and-swap state."""


class OrchestrationTransitionError(ValueError):
    """An illegal lifecycle transition or missing outcome evidence."""


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class OrchestrationStore:
    def __init__(self, db: Database) -> None:
        self.db: Database = db

    @contextmanager
    def _transaction(self) -> Generator[None]:
        with self.db.transaction():
            yield

    def _get(self, model: type[Record], org_id: str, record_id: str) -> Record:
        _ = _IDENTIFIER.validate_python(org_id, strict=True)
        _ = _IDENTIFIER.validate_python(record_id, strict=True)
        table, key = _TABLES[model]
        row = self.db.fetchone(
            f"SELECT payload_json FROM {table} WHERE org_id = ? AND {key} = ?",  # noqa: S608
            (org_id, record_id),
        )
        if row is None:
            raise OrchestrationNotFoundError("Orchestration record not found")
        return model.model_validate_json(cast("str", row["payload_json"]))

    def _list(
        self,
        model: type[Record],
        org_id: str,
        *,
        incident_id: str | None = None,
        task_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Record]:
        _ = _IDENTIFIER.validate_python(org_id, strict=True)
        if (
            type(limit) is not int
            or not 1 <= limit <= 200
            or type(offset) is not int
            or offset < 0
        ):
            raise ValueError("limit must be 1..200 and offset nonnegative")
        table, key = _TABLES[model]
        where = ["org_id = ?"]
        params: list[object] = [org_id]
        for column, value in (
            ("incident_id", incident_id),
            ("task_id", task_id),
            ("status", status),
        ):
            if value is not None:
                _ = _IDENTIFIER.validate_python(value, strict=True)
                where.append(f"{column} = ?")
                params.append(value)
        params.extend((limit, offset))
        direction = "DESC" if newest_first else "ASC"
        rows = self.db.fetchall(
            f"SELECT payload_json FROM {table} WHERE {' AND '.join(where)} ORDER BY created_at {direction}, {key} {direction} LIMIT ? OFFSET ?",  # noqa: S608
            tuple(params),
        )
        return [
            model.model_validate_json(cast("str", row["payload_json"])) for row in rows
        ]

    def _insert(
        self, record: DurableRecord, *, request_hash: str | None = None
    ) -> None:
        table, key = _TABLES[type(record)]
        data = cast("dict[str, object]", record.model_dump(mode="json"))
        payload = record.model_dump_json()
        if len(payload.encode("utf-8")) > 262144:
            raise ValueError("record payload exceeds 256 KiB")
        columns = ["org_id", key, "incident_id", "created_at", "payload_json"]
        values: list[object] = [
            data["org_id"],
            data[key],
            data["incident_id"],
            data["created_at"],
            payload,
        ]
        for column in (
            "task_id",
            "status",
            "parent_task_id",
            "idempotency_key",
            "attempt_id",
        ):
            if column in data and column != key:
                columns.append(column)
                values.append(data[column])
        if isinstance(record, ActionAttemptEvent):
            # Events retain status inside their immutable JSON body.
            status_index = columns.index("status")
            _ = columns.pop(status_index)
            _ = values.pop(status_index)
        if isinstance(record, Task):
            columns.append("request_hash")
            values.append(request_hash)
        _ = self.db.execute(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",  # noqa: S608
            tuple(values),
        )

    def create_task(
        self,
        org_id: str,
        incident_id: str,
        area: str,
        role: str,
        objective: str,
        *,
        parent_task_id: str | None = None,
        priority: int = 100,
        idempotency_key: str | None = None,
    ) -> Task:
        task = Task(
            org_id=org_id,
            incident_id=incident_id,
            area=area,
            role=role,
            objective=objective,
            parent_task_id=parent_task_id,
            priority=priority,
            idempotency_key=idempotency_key,
        )
        request_hash = _hash(
            task.model_dump(
                mode="json",
                include={
                    "org_id",
                    "incident_id",
                    "area",
                    "role",
                    "objective",
                    "parent_task_id",
                    "priority",
                },
            )
        )
        with self._transaction():
            if idempotency_key is not None:
                existing = self.db.fetchone(
                    "SELECT request_hash, payload_json FROM orchestration_tasks WHERE org_id=? AND idempotency_key=?",
                    (org_id, idempotency_key),
                )
                if existing:
                    if existing["request_hash"] != request_hash:
                        raise OrchestrationConflictError(
                            "Idempotency key already used for a different task"
                        )
                    return Task.model_validate_json(
                        cast("str", existing["payload_json"])
                    )
            if parent_task_id is not None:
                parent = self.get_task(org_id, parent_task_id)
                if parent.incident_id != incident_id:
                    raise OrchestrationNotFoundError("Orchestration record not found")
            if not self.db.fetchone(
                "SELECT 1 FROM organizations WHERE org_id=?", (org_id,)
            ):
                raise OrchestrationNotFoundError("Orchestration record not found")
            self._insert(task, request_hash=request_hash)
        return task

    def create_incident_task(
        self,
        org_id: str,
        incident_id: str,
        area: str,
        role: str,
        objective: str,
        *,
        parent_task_id: str | None = None,
        priority: int = 100,
        idempotency_key: str | None = None,
    ) -> Task:
        """Production admission validates the canonical incident in this tenant.

        create_task remains the low-level legacy/import record interface.
        This admission method does not schedule or start a worker.
        """
        if not self.db.fetchone(
            "SELECT 1 FROM incidents WHERE org_id=? AND ticket_id=?",
            (org_id, incident_id),
        ):
            raise OrchestrationNotFoundError("Orchestration record not found")
        return self.create_task(
            org_id,
            incident_id,
            area,
            role,
            objective,
            parent_task_id=parent_task_id,
            priority=priority,
            idempotency_key=idempotency_key,
        )

    def get_task(self, org_id: str, task_id: str) -> Task:
        return self._get(Task, org_id, task_id)

    def list_tasks(
        self,
        org_id: str,
        *,
        incident_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Task]:
        return self._list(
            Task,
            org_id,
            incident_id=incident_id,
            status=status,
            limit=limit,
            offset=offset,
            newest_first=newest_first,
        )

    def create_agent_run(
        self,
        org_id: str,
        task_id: str,
        *,
        agent_id: str | None = None,
        model_connection_id: str | None = None,
        model_name: str | None = None,
    ) -> AgentRun:
        task = self.get_task(org_id, task_id)
        run = AgentRun(
            org_id=org_id,
            incident_id=task.incident_id,
            task_id=task_id,
            agent_id=agent_id,
            model_connection_id=model_connection_id,
            model_name=model_name,
        )
        self._insert(run)
        return run

    def get_agent_run(self, org_id: str, run_id: str) -> AgentRun:
        return self._get(AgentRun, org_id, run_id)

    def list_agent_runs(
        self,
        org_id: str,
        *,
        task_id: str | None = None,
        incident_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AgentRun]:
        return self._list(
            AgentRun,
            org_id,
            task_id=task_id,
            incident_id=incident_id,
            limit=limit,
            offset=offset,
        )

    def create_evidence(
        self,
        org_id: str,
        task_id: str,
        source: str,
        source_timestamp: datetime,
        *,
        content: JsonValue = None,
        content_ref: str | None = None,
    ) -> EvidenceRecord:
        task = self.get_task(org_id, task_id)
        evidence = EvidenceRecord(
            org_id=org_id,
            incident_id=task.incident_id,
            task_id=task_id,
            source=source,
            source_timestamp=source_timestamp,
            content=content,
            content_ref=content_ref,
            content_hash=_hash({"content": content, "content_ref": content_ref}),
        )
        self._insert(evidence)
        return evidence

    def get_evidence(self, org_id: str, evidence_id: str) -> EvidenceRecord:
        return self._get(EvidenceRecord, org_id, evidence_id)

    def list_evidence(
        self,
        org_id: str,
        *,
        task_id: str | None = None,
        incident_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[EvidenceRecord]:
        return self._list(
            EvidenceRecord,
            org_id,
            task_id=task_id,
            incident_id=incident_id,
            limit=limit,
            offset=offset,
        )

    def create_help_request(
        self, org_id: str, task_id: str, requested_role: str, reason: str
    ) -> HelpRequest:
        task = self.get_task(org_id, task_id)
        request = HelpRequest(
            org_id=org_id,
            incident_id=task.incident_id,
            task_id=task_id,
            requested_role=requested_role,
            reason=reason,
        )
        self._insert(request)
        return request

    def get_help_request(self, org_id: str, help_request_id: str) -> HelpRequest:
        return self._get(HelpRequest, org_id, help_request_id)

    def list_help_requests(
        self,
        org_id: str,
        *,
        task_id: str | None = None,
        incident_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[HelpRequest]:
        return self._list(
            HelpRequest,
            org_id,
            task_id=task_id,
            incident_id=incident_id,
            limit=limit,
            offset=offset,
        )

    def create_action_attempt(
        self,
        org_id: str,
        task_id: str,
        action: str,
        targets: list[str],
        *,
        inputs: dict[str, JsonValue] | None = None,
        actor: str = "system",
    ) -> ActionAttempt:
        task = self.get_task(org_id, task_id)
        attempt = ActionAttempt(
            org_id=org_id,
            incident_id=task.incident_id,
            task_id=task_id,
            action=action,
            targets=targets,
            inputs={} if inputs is None else inputs,
        )
        event = ActionAttemptEvent(
            org_id=org_id,
            incident_id=task.incident_id,
            attempt_id=attempt.attempt_id,
            status="proposed",
            actor=actor,
        )
        with self._transaction():
            self._insert(attempt)
            self._insert(event)
        return attempt

    def get_action_attempt(self, org_id: str, attempt_id: str) -> ActionAttempt:
        return self._get(ActionAttempt, org_id, attempt_id)

    def list_action_attempts(
        self,
        org_id: str,
        *,
        task_id: str | None = None,
        incident_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ActionAttempt]:
        return self._list(
            ActionAttempt,
            org_id,
            task_id=task_id,
            incident_id=incident_id,
            limit=limit,
            offset=offset,
        )

    def list_action_events(
        self, org_id: str, attempt_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[ActionAttemptEvent]:
        _ = self.get_action_attempt(org_id, attempt_id)
        if (
            type(limit) is not int
            or not 1 <= limit <= 200
            or type(offset) is not int
            or offset < 0
        ):
            raise ValueError("limit must be 1..200 and offset nonnegative")
        rows = self.db.fetchall(
            "SELECT payload_json FROM orchestration_action_events WHERE org_id=? AND attempt_id=? ORDER BY sequence LIMIT ? OFFSET ?",
            (org_id, attempt_id, limit, offset),
        )
        return [
            ActionAttemptEvent.model_validate_json(cast("str", row["payload_json"]))
            for row in rows
        ]

    def _transition(
        self,
        model: type[Record],
        org_id: str,
        record_id: str,
        expected_status: str,
        status: str,
        **updates: object,
    ) -> Record:
        record = self._get(model, org_id, record_id)
        current = cast("dict[str, object]", record.model_dump())
        if current["status"] != expected_status:
            raise OrchestrationConflictError("Record status changed")
        if status not in _TRANSITIONS[model].get(expected_status, set()):
            raise OrchestrationTransitionError("Illegal lifecycle transition")
        now = utc_now()
        current.update(status=status, updated_at=now, **updates)
        if (
            "started_at" in current
            and status == "running"
            and current["started_at"] is None
        ):
            current["started_at"] = now
        if status in {
            "completed",
            "failed",
            "cancelled",
            "resolved",
            "verified",
            "rejected",
        }:
            current["completed_at"] = now
        updated = model.model_validate(current)
        payload = updated.model_dump_json()
        if len(payload.encode("utf-8")) > 262144:
            raise ValueError("record payload exceeds 256 KiB")
        table, key = _TABLES[model]
        cursor = self.db.execute(
            f"UPDATE {table} SET status=?,payload_json=? WHERE org_id=? AND {key}=? AND status=?",  # noqa: S608
            (status, payload, org_id, record_id, expected_status),
        )
        if cursor.rowcount != 1:
            _ = self._get(model, org_id, record_id)
            raise OrchestrationConflictError("Record status changed")
        return updated

    def transition_task(
        self, org_id: str, task_id: str, expected_status: TaskStatus, status: TaskStatus
    ) -> Task:
        return self._transition(Task, org_id, task_id, expected_status, status)

    def transition_agent_run(
        self,
        org_id: str,
        run_id: str,
        expected_status: RunStatus,
        status: RunStatus,
        *,
        result: JsonValue = None,
        error: str | None = None,
    ) -> AgentRun:
        if status == "failed" and not error:
            _ = self.get_agent_run(org_id, run_id)
            raise OrchestrationTransitionError("Failed runs require an error")
        return self._transition(
            AgentRun,
            org_id,
            run_id,
            expected_status,
            status,
            result=result,
            error=error,
        )

    def transition_help_request(
        self,
        org_id: str,
        help_request_id: str,
        expected_status: HelpStatus,
        status: HelpStatus,
    ) -> HelpRequest:
        return self._transition(
            HelpRequest, org_id, help_request_id, expected_status, status
        )

    def transition_action_attempt(
        self,
        org_id: str,
        attempt_id: str,
        expected_status: ActionStatus,
        status: ActionStatus,
        *,
        actor: str,
        outputs: dict[str, JsonValue] | None = None,
        error: str | None = None,
    ) -> ActionAttempt:
        with self._transaction():
            attempt = self.get_action_attempt(org_id, attempt_id)
            if status == "verified" and not outputs:
                raise OrchestrationTransitionError(
                    "Verification requires recorded outcome evidence"
                )
            if status in {"failed", "unknown"} and not error:
                raise OrchestrationTransitionError(
                    "Failed or unknown actions require an error/reason"
                )
            event = ActionAttemptEvent(
                org_id=org_id,
                incident_id=attempt.incident_id,
                attempt_id=attempt_id,
                status=status,
                actor=actor,
                outputs={} if outputs is None else outputs,
                error=error,
            )
            updated = self._transition(
                ActionAttempt, org_id, attempt_id, expected_status, status
            )
            self._insert(event)
        return updated
