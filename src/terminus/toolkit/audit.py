"""Durable, fenced invocation admission. No handlers or providers run here."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import uuid4

from pydantic import Field, TypeAdapter

from terminus.orchestration.models import AgentRun, EvidenceRecord, Task, utc_now
from terminus.storage.db import Database
from terminus.toolkit.catalog import CORE_ROLES
from terminus.toolkit.models import (
    Contract,
    Digest,
    Id,
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
    ToolInvocation,
    ToolResult,
)


class ToolAuditError(ValueError):
    def __init__(self, message: str, *, code: str = "stale_ownership") -> None:
        super().__init__(message)
        self.code: str = code


class ToolQuotaError(ToolAuditError):
    def __init__(self) -> None:
        super().__init__(
            "Task has exhausted its 20 tool attempts", code="quota_exhausted"
        )


def canonical_query_digest(query: ReadQuery) -> str:
    payload = json.dumps(
        query.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _lease_digest(context: ToolExecutionContext) -> str:
    lease = context.lease
    # Do not persist bearer-like worker or coordinator fencing tokens verbatim.
    return hashlib.sha256(
        json.dumps(
            [
                lease.job_id,
                lease.run_id,
                lease.worker_id,
                lease.lease_token,
                lease.coordinator_owner_id,
                lease.coordinator_token,
                lease.attempt,
            ],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


class InvocationReservation(Contract):
    invocation_id: Id
    org_id: Id
    incident_id: Id
    task_id: Id
    run_id: Id
    tool_id: Id
    tool_version: Literal["1.0"]
    effect: Literal["read", "local_analysis"]
    connector_ids: tuple[Id, ...] = ()
    arguments_digest: Digest
    policy_version: Id
    timestamp: datetime
    lease_digest: Digest
    max_output_bytes: int = Field(ge=1, le=65536)
    timeout_seconds: int = Field(ge=1, le=10)


class ToolInvocationStore:
    """Append-only reservation and completion records with a task-wide quota.

    Unfinished reservations survive restart and consume quota. Finishing cannot
    release a slot, alter its digest, or publish a success after ownership loss.
    Denied requests have a separate audit trail and never enter a handler.
    """

    def __init__(
        self, db: Database, *, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self.db: Database = db
        self.clock: Callable[[], datetime] = clock
        with db.transaction() as conn:
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS toolkit_invocation_reservations (
                org_id TEXT NOT NULL, invocation_id TEXT NOT NULL,
                incident_id TEXT NOT NULL, task_id TEXT NOT NULL, run_id TEXT NOT NULL,
                created_at TEXT NOT NULL, payload_json TEXT NOT NULL,
                PRIMARY KEY(org_id, invocation_id),
                FOREIGN KEY(org_id, incident_id, task_id)
                    REFERENCES orchestration_tasks(org_id, incident_id, task_id),
                FOREIGN KEY(org_id, run_id)
                    REFERENCES orchestration_agent_runs(org_id, run_id)
            )""")
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS toolkit_invocation_completions (
                org_id TEXT NOT NULL, invocation_id TEXT NOT NULL,
                payload_json TEXT NOT NULL, PRIMARY KEY(org_id, invocation_id),
                FOREIGN KEY(org_id, invocation_id)
                    REFERENCES toolkit_invocation_reservations(org_id, invocation_id)
            )""")
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS toolkit_invocation_denials (
                org_id TEXT NOT NULL, invocation_id TEXT NOT NULL,
                incident_id TEXT NOT NULL, task_id TEXT NOT NULL, run_id TEXT NOT NULL,
                created_at TEXT NOT NULL, error_code TEXT NOT NULL,
                payload_json TEXT NOT NULL, PRIMARY KEY(org_id, invocation_id),
                FOREIGN KEY(org_id, incident_id, task_id)
                    REFERENCES orchestration_tasks(org_id, incident_id, task_id),
                FOREIGN KEY(org_id, run_id)
                    REFERENCES orchestration_agent_runs(org_id, run_id)
            )""")
            _ = conn.execute("""CREATE INDEX IF NOT EXISTS idx_toolkit_reservations_task
                ON toolkit_invocation_reservations(org_id,task_id,created_at)""")
            for table in (
                "toolkit_invocation_reservations",
                "toolkit_invocation_completions",
                "toolkit_invocation_denials",
            ):
                for operation in ("UPDATE", "DELETE"):
                    _ = conn.execute(
                        f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()}
                        BEFORE {operation} ON {table}
                        BEGIN SELECT RAISE(ABORT, 'tool audit is immutable'); END"""
                    )

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("audit clock requires an aware timestamp")
        return now.astimezone(UTC)

    def _scope(self, context: ToolExecutionContext) -> tuple[Task, AgentRun]:
        task_row = self.db.fetchone(
            "SELECT * FROM orchestration_tasks WHERE org_id=? AND task_id=? AND incident_id=?",
            (context.org_id, context.task_id, context.incident_id),
        )
        run_row = self.db.fetchone(
            """SELECT * FROM orchestration_agent_runs WHERE org_id=? AND run_id=?
            AND task_id=? AND incident_id=?""",
            (context.org_id, context.run_id, context.task_id, context.incident_id),
        )
        if not task_row or not run_row:
            raise ToolAuditError("Unknown scoped task or run")
        task = Task.model_validate_json(cast("str", task_row["payload_json"]))
        run = AgentRun.model_validate_json(cast("str", run_row["payload_json"]))
        if (
            (task.org_id, task.incident_id, task.task_id)
            != (context.org_id, context.incident_id, context.task_id)
            or (run.org_id, run.incident_id, run.task_id, run.run_id)
            != (context.org_id, context.incident_id, context.task_id, context.run_id)
            or task.status != task_row["status"]
            or run.status != run_row["status"]
        ):
            raise ToolAuditError("Canonical task/run scope is inconsistent")
        return task, run

    def _owned(self, context: ToolExecutionContext, now: datetime) -> None:
        task, run = self._scope(context)
        lease = context.lease
        job = self.db.fetchone(
            "SELECT * FROM orchestration_scheduler_jobs WHERE org_id=? AND task_id=?",
            (context.org_id, context.task_id),
        )
        coordinator = self.db.fetchone(
            "SELECT * FROM orchestration_scheduler_coordinator WHERE singleton=1"
        )
        if (
            context.cancelled
            or task.status != "running"
            or run.status != "running"
            or task.role != context.role
            or task.role not in CORE_ROLES
            or not job
            or job["status"] != "running"
            or job["cancellation_requested"]
            or job["role"] != context.role
            or job["incident_id"] != context.incident_id
            or job["job_id"] != lease.job_id
            or job["run_id"] != context.run_id
            or job["worker_id"] != lease.worker_id
            or job["lease_token"] != lease.lease_token
            or job["attempt"] != lease.attempt
            or not job["lease_expires_at"]
            or datetime.fromisoformat(cast("str", job["lease_expires_at"])) <= now
        ):
            raise ToolAuditError("Tool ownership is cancelled, stale, or expired")
        if (
            not coordinator
            or coordinator["owner_id"] != lease.coordinator_owner_id
            or coordinator["lease_token"] != lease.coordinator_token
            or job["coordinator_owner_id"] != lease.coordinator_owner_id
            or job["coordinator_token"] != lease.coordinator_token
            or datetime.fromisoformat(cast("str", coordinator["lease_expires_at"]))
            <= now
        ):
            raise ToolAuditError("Coordinator ownership is stale or expired")

    def reserve(
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
    ) -> InvocationReservation:
        descriptor = ToolDescriptor.model_validate(descriptor.model_dump())
        context = ToolExecutionContext.model_validate(context.model_dump())
        query = ReadQuery.model_validate(query.model_dump())
        if (
            descriptor.effect not in {"read", "local_analysis"}
            or descriptor.input_contract != "read_query"
            or descriptor.release != "1.0"
            or descriptor.availability != "available"
            or context.role not in descriptor.permitted_roles
            or descriptor.tool_id not in context.granted_tool_ids
            or query.resource_id not in context.permitted_resource_ids
            or not set(descriptor.connector_ids) <= set(context.permitted_connector_ids)
            or (
                descriptor.egress == "policy_required" and not context.egress_authorized
            )
            or (query.end - query.start).total_seconds()
            > descriptor.limits.window_seconds
            or query.page_size > descriptor.limits.page_size
            or query.max_pages > descriptor.limits.max_pages
        ):
            raise ToolAuditError(
                "Tool request is outside the read grant", code="denied"
            )
        with self.db.transaction():
            now = self._now()
            self._owned(context, now)
            if self.count(context.org_id, context.task_id) >= 20:
                raise ToolQuotaError
            reservation = InvocationReservation(
                invocation_id=str(uuid4()),
                org_id=context.org_id,
                incident_id=context.incident_id,
                task_id=context.task_id,
                run_id=context.run_id,
                tool_id=descriptor.tool_id,
                tool_version=descriptor.version,
                effect=cast("Literal['read', 'local_analysis']", descriptor.effect),
                connector_ids=descriptor.connector_ids,
                arguments_digest=canonical_query_digest(query),
                policy_version=context.policy_version,
                timestamp=now,
                lease_digest=_lease_digest(context),
                max_output_bytes=descriptor.limits.max_output_bytes,
                timeout_seconds=descriptor.limits.timeout_seconds,
            )
            _ = self.db.execute(
                "INSERT INTO toolkit_invocation_reservations VALUES(?,?,?,?,?,?,?)",
                (
                    reservation.org_id,
                    reservation.invocation_id,
                    reservation.incident_id,
                    reservation.task_id,
                    reservation.run_id,
                    now.isoformat(),
                    reservation.model_dump_json(),
                ),
            )
            return reservation

    def count(self, org_id: str, task_id: str) -> int:
        row = self.db.fetchone(
            "SELECT count(*) AS n FROM toolkit_invocation_reservations WHERE org_id=? AND task_id=?",
            (org_id, task_id),
        )
        return cast("int", row["n"]) if row else 0

    def assert_pending(
        self,
        context: ToolExecutionContext,
        descriptor: ToolDescriptor,
        query: ReadQuery,
    ) -> InvocationReservation:
        """Fence evidence writes by the handler's bound invocation identity.

        Call inside the evidence writer's transaction, so a completion or
        cancellation cannot interleave with a successful admission and write.
        """
        context = ToolExecutionContext.model_validate(context.model_dump())
        descriptor = ToolDescriptor.model_validate(descriptor.model_dump())
        query = ReadQuery.model_validate(query.model_dump())
        with self.db.transaction():
            row = self.db.fetchone(
                "SELECT payload_json FROM toolkit_invocation_reservations WHERE org_id=? AND invocation_id=?",
                (context.org_id, context.invocation_id),
            )
            if not row:
                raise ToolAuditError("No pending invocation for this handler")
            reservation = InvocationReservation.model_validate_json(
                cast("str", row["payload_json"])
            )
            if (
                reservation.org_id,
                reservation.incident_id,
                reservation.task_id,
                reservation.run_id,
                reservation.tool_id,
                reservation.tool_version,
                reservation.effect,
                reservation.connector_ids,
                reservation.policy_version,
                reservation.arguments_digest,
                reservation.lease_digest,
                reservation.max_output_bytes,
                reservation.timeout_seconds,
            ) != (
                context.org_id,
                context.incident_id,
                context.task_id,
                context.run_id,
                descriptor.tool_id,
                descriptor.version,
                descriptor.effect,
                descriptor.connector_ids,
                context.policy_version,
                canonical_query_digest(query),
                _lease_digest(context),
                descriptor.limits.max_output_bytes,
                descriptor.limits.timeout_seconds,
            ) or self.db.fetchone(
                "SELECT 1 FROM toolkit_invocation_completions WHERE org_id=? AND invocation_id=?",
                (context.org_id, reservation.invocation_id),
            ):
                raise ToolAuditError(
                    "Invocation is completed or does not match this handler"
                )
            now = self._now()
            if now >= reservation.timestamp + timedelta(
                seconds=reservation.timeout_seconds
            ):
                raise ToolAuditError("Invocation deadline has expired")
            self._owned(context, now)
            return reservation

    def finish(
        self,
        reservation: InvocationReservation,
        context: ToolExecutionContext,
        result: ToolResult | None = None,
        *,
        uncertain: bool = False,
    ) -> ToolInvocation:
        reservation = InvocationReservation.model_validate(reservation.model_dump())
        context = ToolExecutionContext.model_validate(context.model_dump())
        with self.db.transaction():
            row = self.db.fetchone(
                "SELECT payload_json FROM toolkit_invocation_reservations WHERE org_id=? AND invocation_id=?",
                (context.org_id, reservation.invocation_id),
            )
            if (
                not row
                or InvocationReservation.model_validate_json(
                    cast("str", row["payload_json"])
                )
                != reservation
                or (
                    reservation.org_id,
                    reservation.incident_id,
                    reservation.task_id,
                    reservation.run_id,
                )
                != (
                    context.org_id,
                    context.incident_id,
                    context.task_id,
                    context.run_id,
                )
                or reservation.lease_digest != _lease_digest(context)
                or reservation.policy_version != context.policy_version
            ):
                raise ToolAuditError("Reservation does not belong to this execution")
            completed = self.db.fetchone(
                "SELECT payload_json FROM toolkit_invocation_completions WHERE org_id=? AND invocation_id=?",
                (context.org_id, reservation.invocation_id),
            )
            if completed:
                return ToolInvocation.model_validate_json(
                    cast("str", completed["payload_json"])
                )
            now = self._now()
            if now >= reservation.timestamp + timedelta(
                seconds=reservation.timeout_seconds
            ):
                uncertain = True
            try:
                self._owned(context, now)
            except ToolAuditError:
                uncertain = True
            if result is None:
                uncertain = True
            elif not uncertain:
                result = ToolResult.model_validate(result.model_dump())
                self._validate_result(reservation, result)
            versions = (
                ()
                if uncertain or result is None
                else tuple(
                    sorted(
                        {
                            (p.connector_id, p.connector_version)
                            for p in result.provenance
                        }
                    )
                )
            )
            invocation = ToolInvocation(
                invocation_id=reservation.invocation_id,
                org_id=reservation.org_id,
                incident_id=reservation.incident_id,
                task_id=reservation.task_id,
                run_id=reservation.run_id,
                tool_id=reservation.tool_id,
                tool_version=reservation.tool_version,
                effect=reservation.effect,
                connector_id=versions[0][0] if len(versions) == 1 else None,
                connector_version=versions[0][1] if len(versions) == 1 else None,
                connector_versions=versions,
                arguments_digest=reservation.arguments_digest,
                policy_version=reservation.policy_version,
                policy_decision="allowed",
                outcome="unknown" if uncertain or result is None else result.status,
                timestamp=self._now(),
                evidence_ids=()
                if uncertain or result is None
                else tuple(ref.evidence_id for ref in result.evidence),
            )
            _ = self.db.execute(
                "INSERT INTO toolkit_invocation_completions VALUES(?,?,?)",
                (
                    invocation.org_id,
                    invocation.invocation_id,
                    invocation.model_dump_json(),
                ),
            )
            return invocation

    def _validate_result(
        self, reservation: InvocationReservation, result: ToolResult
    ) -> None:
        if any(
            item.connector_id not in reservation.connector_ids
            for item in result.provenance
        ):
            raise ToolAuditError(
                "Connector is outside the reservation", code="invalid_result"
            )
        if (result.tool_id, result.version) != (
            reservation.tool_id,
            reservation.tool_version,
        ):
            raise ToolAuditError(
                "Unexpected tool result identity", code="invalid_result"
            )
        if (
            len(json.dumps(result.model_dump(mode="json")).encode())
            > reservation.max_output_bytes
        ):
            raise ToolAuditError(
                "Tool result exceeds its output limit", code="invalid_result"
            )
        for ref in result.evidence:
            row = self.db.fetchone(
                "SELECT payload_json FROM orchestration_evidence WHERE org_id=? AND incident_id=? AND evidence_id=?",
                (reservation.org_id, reservation.incident_id, ref.evidence_id),
            )
            if (ref.org_id, ref.incident_id) != (
                reservation.org_id,
                reservation.incident_id,
            ) or not row:
                raise ToolAuditError(
                    "Evidence is outside the incident", code="invalid_result"
                )
            record = EvidenceRecord.model_validate_json(
                cast("str", row["payload_json"])
            )
            if record.content_hash != ref.content_hash:
                raise ToolAuditError("Evidence hash differs", code="invalid_result")

    def record_denial(
        self,
        context: ToolExecutionContext,
        tool_id: str,
        arguments_digest: str,
        error_code: str,
    ) -> ToolInvocation:
        context = ToolExecutionContext.model_validate(context.model_dump())
        TypeAdapter(Id).validate_python(tool_id, strict=True)
        TypeAdapter(Id).validate_python(error_code, strict=True)
        TypeAdapter(Digest).validate_python(arguments_digest, strict=True)
        with self.db.transaction():
            _ = self._scope(context)
            denial_count = self.db.fetchone(
                "SELECT count(*) AS n FROM toolkit_invocation_denials WHERE org_id=? AND task_id=?",
                (context.org_id, context.task_id),
            )
            if denial_count and denial_count["n"] >= 20:
                raise ToolAuditError(
                    "Task denial audit quota exhausted", code="denial_quota_exhausted"
                )
            invocation = ToolInvocation(
                invocation_id=str(uuid4()),
                org_id=context.org_id,
                incident_id=context.incident_id,
                task_id=context.task_id,
                run_id=context.run_id,
                tool_id=tool_id,
                tool_version="1.0",
                effect="read",
                arguments_digest=arguments_digest,
                policy_version=context.policy_version,
                policy_decision="denied",
                outcome="denied",
                timestamp=self._now(),
            )
            _ = self.db.execute(
                "INSERT INTO toolkit_invocation_denials VALUES(?,?,?,?,?,?,?,?)",
                (
                    invocation.org_id,
                    invocation.invocation_id,
                    invocation.incident_id,
                    invocation.task_id,
                    invocation.run_id,
                    invocation.timestamp.isoformat(),
                    error_code,
                    invocation.model_dump_json(),
                ),
            )
            return invocation

    def list_invocations(self, org_id: str, task_id: str) -> list[ToolInvocation]:
        rows = self.db.fetchall(
            """SELECT c.payload_json FROM toolkit_invocation_completions c
            JOIN toolkit_invocation_reservations r USING(org_id,invocation_id)
            WHERE r.org_id=? AND r.task_id=? UNION ALL
            SELECT payload_json FROM toolkit_invocation_denials WHERE org_id=? AND task_id=?""",
            (org_id, task_id, org_id, task_id),
        )
        return sorted(
            (
                ToolInvocation.model_validate_json(cast("str", row["payload_json"]))
                for row in rows
            ),
            key=lambda record: (record.timestamp, record.invocation_id),
        )

    def list_pending(self, org_id: str, task_id: str) -> list[InvocationReservation]:
        rows = self.db.fetchall(
            """SELECT r.payload_json FROM toolkit_invocation_reservations r
            LEFT JOIN toolkit_invocation_completions c USING(org_id,invocation_id)
            WHERE r.org_id=? AND r.task_id=? AND c.invocation_id IS NULL ORDER BY r.created_at,r.invocation_id""",
            (org_id, task_id),
        )
        return [
            InvocationReservation.model_validate_json(cast("str", row["payload_json"]))
            for row in rows
        ]
