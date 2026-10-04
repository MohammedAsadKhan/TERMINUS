"""Atomic durable admission, coordinator ownership, job leases and recovery.

Only explicitly enqueued tasks are eligible. No provider or action is invoked
here; uncertain action outcomes always require reconciliation before retry.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from pydantic import JsonValue, TypeAdapter

from terminus.orchestration.models import AgentRun, Identifier, Label, Task, utc_now
from terminus.orchestration.scheduler_models import (
    CoordinatorLease,
    JobLease,
    SchedulerJob,
)
from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
)
from terminus.storage.db import Database

_IDENTIFIER = TypeAdapter(Identifier)
_ROLE = TypeAdapter(Label)
_JOB_COLUMNS = (
    "org_id",
    "incident_id",
    "task_id",
    "role",
    "priority",
    "status",
    "attempt",
    "max_attempts",
    "available_at",
    "worker_id",
    "lease_token",
    "lease_expires_at",
    "heartbeat_at",
    "run_id",
    "cancellation_requested",
    "error",
    "recovery_reason",
    "coordinator_owner_id",
    "coordinator_token",
    "created_at",
    "updated_at",
)
_TERMINAL = {"completed", "failed", "cancelled"}
_JOB_TIMESTAMPS = (
    "available_at",
    "lease_expires_at",
    "heartbeat_at",
    "created_at",
    "updated_at",
)


class SchedulerLeaseError(OrchestrationConflictError):
    """Ownership expired, was fenced, or was cancelled before renewal."""


def _seconds(value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= 3600
    ):
        raise ValueError("lease_seconds must be finite and in (0, 3600]")
    return float(value)


def _bounded_payload(record: Task | AgentRun | SchedulerJob) -> str:
    payload = record.model_dump_json()
    if len(payload.encode("utf-8")) > 262144:
        raise ValueError("record payload exceeds 256 KiB")
    return payload


def _sql_time(value: datetime) -> str:
    # SQLite compares these indexed columns as text. A fixed UTC representation
    # preserves ordering at exact-second boundaries and for subsecond leases.
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _job_data(job: SchedulerJob) -> dict[str, Any]:
    data = job.model_dump(mode="json")
    for column in _JOB_TIMESTAMPS:
        value = getattr(job, column)
        data[column] = _sql_time(value) if value is not None else None
    return data


class SchedulerStore:
    def __init__(
        self, db: Database, *, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self.db = db
        self.records = OrchestrationStore(db)
        self.clock = clock
        self._coordinators: dict[str, str] = {}

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scheduler clock must return an aware datetime")
        return value.astimezone(UTC)

    def enqueue_task(
        self, org_id: str, task_id: str, *, max_attempts: int = 3
    ) -> SchedulerJob:
        if type(max_attempts) is not int or not 1 <= max_attempts <= 5:
            raise ValueError("max_attempts must be an integer in 1..5")
        with self.db.transaction():
            task = self.records.get_task(org_id, task_id)
            if not self.db.fetchone(
                "SELECT 1 FROM incidents WHERE org_id=? AND ticket_id=?",
                (org_id, task.incident_id),
            ):
                raise OrchestrationNotFoundError("Orchestration record not found")
            row = self.db.fetchone(
                "SELECT payload_json FROM orchestration_scheduler_jobs "
                "WHERE org_id=? AND task_id=?",
                (org_id, task_id),
            )
            if row:
                job = self._decode(row)
                if job.max_attempts != max_attempts:
                    raise OrchestrationConflictError(
                        "Task already admitted with different scheduler configuration"
                    )
                return job
            if task.status != "queued":
                raise OrchestrationConflictError("Only queued tasks can be admitted")
            now = self._now()
            job = SchedulerJob(
                org_id=org_id,
                incident_id=task.incident_id,
                task_id=task_id,
                role=task.role,
                priority=task.priority,
                max_attempts=max_attempts,
                available_at=now,
                created_at=now,
                updated_at=now,
            )
            data = _job_data(job)
            columns = ("job_id", *_JOB_COLUMNS, "payload_json")
            values = [data[column] for column in columns[:-1]]
            values.append(_bounded_payload(job))
            self.db.execute(
                "INSERT INTO orchestration_scheduler_jobs "  # noqa: S608
                f"({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                tuple(values),
            )
            return job

    @staticmethod
    def _decode(row: dict[str, Any]) -> SchedulerJob:
        return SchedulerJob.model_validate_json(row["payload_json"])

    def get_job(self, org_id: str, task_id: str) -> SchedulerJob:
        _IDENTIFIER.validate_python(org_id, strict=True)
        _IDENTIFIER.validate_python(task_id, strict=True)
        row = self.db.fetchone(
            "SELECT payload_json FROM orchestration_scheduler_jobs "
            "WHERE org_id=? AND task_id=?",
            (org_id, task_id),
        )
        if row is None:
            raise OrchestrationNotFoundError("Orchestration record not found")
        return self._decode(row)

    def list_jobs(
        self,
        org_id: str,
        *,
        incident_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[SchedulerJob]:
        _IDENTIFIER.validate_python(org_id, strict=True)
        if (
            type(limit) is not int
            or not 1 <= limit <= 200
            or type(offset) is not int
            or offset < 0
        ):
            raise ValueError("limit must be 1..200 and offset nonnegative")
        where, params = ["org_id=?"], [org_id]
        for name, value in (("incident_id", incident_id), ("status", status)):
            if value is not None:
                _IDENTIFIER.validate_python(value, strict=True)
                where.append(f"{name}=?")
                params.append(value)
        return [
            self._decode(row)
            for row in self.db.fetchall(
                "SELECT payload_json FROM orchestration_scheduler_jobs "  # noqa: S608
                f"WHERE {' AND '.join(where)} ORDER BY sequence LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
        ]

    def acquire_coordinator(
        self, owner_id: str, lease_seconds: float = 30
    ) -> CoordinatorLease | None:
        _IDENTIFIER.validate_python(owner_id, strict=True)
        seconds = _seconds(lease_seconds)
        with self.db.transaction():
            now = self._now()
            row = self.db.fetchone(
                "SELECT * FROM orchestration_scheduler_coordinator WHERE singleton=1"
            )
            if row and datetime.fromisoformat(row["lease_expires_at"]) > now:
                return None
            from secrets import token_urlsafe

            lease = CoordinatorLease(
                owner_id=owner_id,
                lease_token=token_urlsafe(32),
                lease_expires_at=now + timedelta(seconds=seconds),
                created_at=now,
            )
            self.db.execute(
                "INSERT INTO orchestration_scheduler_coordinator "
                "(singleton,owner_id,lease_token,lease_expires_at,heartbeat_at) VALUES (1,?,?,?,?) "
                "ON CONFLICT(singleton) DO UPDATE SET owner_id=excluded.owner_id, "
                "lease_token=excluded.lease_token,lease_expires_at=excluded.lease_expires_at, "
                "heartbeat_at=excluded.heartbeat_at",
                (
                    owner_id,
                    lease.lease_token,
                    lease.lease_expires_at.isoformat(),
                    now.isoformat(),
                ),
            )
            self._coordinators[owner_id] = lease.lease_token
            return lease

    def _require_coordinator(self, owner_id: str, now: datetime) -> None:
        row = self.db.fetchone(
            "SELECT * FROM orchestration_scheduler_coordinator WHERE singleton=1"
        )
        if (
            not row
            or row["owner_id"] != owner_id
            or row["lease_token"] != self._coordinators.get(owner_id)
            or datetime.fromisoformat(row["lease_expires_at"]) <= now
        ):
            raise SchedulerLeaseError("Coordinator ownership is stale or expired")

    def renew_coordinator(
        self, lease: CoordinatorLease, lease_seconds: float = 30
    ) -> CoordinatorLease:
        seconds = _seconds(lease_seconds)
        with self.db.transaction():
            now = self._now()
            self._require_coordinator(lease.owner_id, now)
            if self._coordinators[lease.owner_id] != lease.lease_token:
                raise SchedulerLeaseError("Coordinator fencing token is stale")
            updated = CoordinatorLease.model_validate(
                lease.model_dump()
                | {
                    "lease_expires_at": now + timedelta(seconds=seconds),
                }
            )
            self.db.execute(
                "UPDATE orchestration_scheduler_coordinator SET lease_expires_at=?,heartbeat_at=? "
                "WHERE singleton=1 AND owner_id=? AND lease_token=?",
                (
                    updated.lease_expires_at.isoformat(),
                    now.isoformat(),
                    lease.owner_id,
                    lease.lease_token,
                ),
            )
            return updated

    def release_coordinator(self, lease: CoordinatorLease) -> bool:
        with self.db.transaction():
            count = self.db.execute(
                "DELETE FROM orchestration_scheduler_coordinator "
                "WHERE singleton=1 AND owner_id=? AND lease_token=?",
                (lease.owner_id, lease.lease_token),
            ).rowcount
            if self._coordinators.get(lease.owner_id) == lease.lease_token:
                self._coordinators.pop(lease.owner_id, None)
            return count == 1

    def _save_job(self, job: SchedulerJob) -> None:
        data = _job_data(job)
        payload = _bounded_payload(job)
        self.db.execute(
            "UPDATE orchestration_scheduler_jobs SET "  # noqa: S608
            f"{','.join(f'{column}=?' for column in _JOB_COLUMNS)},payload_json=? "
            "WHERE org_id=? AND task_id=? AND job_id=?",
            (
                *[data[column] for column in _JOB_COLUMNS],
                payload,
                job.org_id,
                job.task_id,
                job.job_id,
            ),
        )

    def _save_record(self, record: Task | AgentRun) -> None:
        table, key = (
            ("orchestration_tasks", "task_id")
            if isinstance(record, Task)
            else ("orchestration_agent_runs", "run_id")
        )
        self.db.execute(
            f"UPDATE {table} SET status=?,payload_json=? WHERE org_id=? AND {key}=?",  # noqa: S608
            (
                record.status,
                _bounded_payload(record),
                record.org_id,
                getattr(record, key),
            ),
        )

    def _uncertain(self, org_id: str, task_id: str) -> bool:
        return bool(
            self.db.fetchone(
                "SELECT 1 FROM orchestration_action_attempts WHERE org_id=? AND task_id=? "
                "AND status IN ('dispatched','acknowledged','unknown') LIMIT 1",
                (org_id, task_id),
            )
        )

    def _previous_dispatch(self, org_id: str, task_id: str) -> bool:
        """An observed effect remains unsafe to replay after later failure.

        Current failed/verified status alone loses whether dispatch happened.
        Immutable action history preserves that distinction from failure before
        dispatch. Successful verified actions can still complete normally.
        """
        return bool(
            self.db.fetchone(
                "SELECT 1 FROM orchestration_action_attempts a "
                "WHERE a.org_id=? AND a.task_id=? AND ("
                "a.status IN ('dispatched','acknowledged','verified','unknown') OR "
                "EXISTS (SELECT 1 FROM orchestration_action_events e "
                "WHERE e.org_id=a.org_id AND e.attempt_id=a.attempt_id "
                "AND json_extract(e.payload_json,'$.status') IN "
                "('dispatched','acknowledged','verified','unknown'))) LIMIT 1",
                (org_id, task_id),
            )
        )

    def claim_next(
        self,
        owner_id: str,
        worker_id: str,
        roles: Iterable[str],
        *,
        lease_seconds: float = 30,
        global_limit: int = 4,
        per_org_limit: int = 2,
    ) -> JobLease | None:
        _IDENTIFIER.validate_python(worker_id, strict=True)
        seconds = _seconds(lease_seconds)
        if any(
            type(value) is not int or not 1 <= value <= 1000
            for value in (global_limit, per_org_limit)
        ):
            raise ValueError("concurrency limits must be integers in 1..1000")
        if isinstance(roles, str):
            raise ValueError("roles must be a collection of role names")
        eligible_roles = sorted(
            {_ROLE.validate_python(role, strict=True) for role in roles}
        )
        if len(eligible_roles) > 100:
            raise ValueError("at most 100 eligible roles")
        with self.db.transaction():
            now = self._now()
            self._require_coordinator(owner_id, now)
            if not eligible_roles:
                return None
            count = self.db.fetchone(
                "SELECT count(*) AS n FROM orchestration_scheduler_jobs WHERE status='running'"
            )
            if count["n"] >= global_limit:
                return None
            rows = self.db.fetchall(
                "SELECT j.payload_json FROM orchestration_scheduler_jobs j "  # noqa: S608
                "WHERE j.status IN ('queued','retry_wait') AND j.available_at<=? "
                "AND j.cancellation_requested=0 AND j.attempt<j.max_attempts "
                f"AND j.role IN ({','.join('?' for _ in eligible_roles)}) "
                "AND (SELECT count(*) FROM orchestration_scheduler_jobs active "
                "WHERE active.org_id=j.org_id AND active.status='running')<? "
                "ORDER BY j.priority DESC,j.sequence",
                (_sql_time(now), *eligible_roles, per_org_limit),
            )
            for row in rows:
                job = self._decode(row)
                task = self.records.get_task(job.org_id, job.task_id)
                if self._uncertain(job.org_id, job.task_id):
                    self._hold(job, task, now, "Action outcome requires reconciliation")
                    continue
                if self._previous_dispatch(job.org_id, job.task_id):
                    self._hold(
                        job,
                        task,
                        now,
                        "Previous action dispatch prevents automatic replay",
                    )
                    continue
                if task.status not in {"queued", "waiting"}:
                    self._save_job(
                        SchedulerJob.model_validate(
                            job.model_dump()
                            | {
                                "status": task.status
                                if task.status in _TERMINAL
                                else "waiting",
                                "updated_at": now,
                                "recovery_reason": "Canonical task changed outside scheduler",
                            }
                        )
                    )
                    continue
                from secrets import token_urlsafe

                task = Task.model_validate(
                    task.model_dump()
                    | {
                        "status": "running",
                        "started_at": task.started_at or now,
                        "updated_at": now,
                        "completed_at": None,
                    }
                )
                run = AgentRun(
                    org_id=job.org_id,
                    incident_id=job.incident_id,
                    task_id=job.task_id,
                    status="running",
                    created_at=now,
                    updated_at=now,
                    started_at=now,
                )
                self.records._insert(run)  # noqa: SLF001
                self._save_record(task)
                job = SchedulerJob.model_validate(
                    job.model_dump()
                    | {
                        "status": "running",
                        "attempt": job.attempt + 1,
                        "worker_id": worker_id,
                        "lease_token": token_urlsafe(32),
                        "lease_expires_at": now + timedelta(seconds=seconds),
                        "heartbeat_at": now,
                        "run_id": run.run_id,
                        "updated_at": now,
                        "coordinator_owner_id": owner_id,
                        "coordinator_token": self._coordinators[owner_id],
                    }
                )
                self._save_job(job)
                return self._lease(job, task, run)
            return None

    @staticmethod
    def _lease(job: SchedulerJob, task: Task, run: AgentRun) -> JobLease:
        return JobLease(
            org_id=job.org_id,
            incident_id=job.incident_id,
            created_at=job.created_at,
            job_id=job.job_id,
            task_id=job.task_id,
            run_id=run.run_id,
            worker_id=cast("str", job.worker_id),
            lease_token=cast("str", job.lease_token),
            lease_expires_at=cast("datetime", job.lease_expires_at),
            attempt=job.attempt,
            task=task,
            run=run,
            coordinator_owner_id=cast("str", job.coordinator_owner_id),
            coordinator_token=cast("str", job.coordinator_token),
        )

    def _owned(self, lease: JobLease, now: datetime) -> SchedulerJob:
        job = self.get_job(lease.org_id, lease.task_id)
        if (
            job.status != "running"
            or job.job_id != lease.job_id
            or job.incident_id != lease.incident_id
            or job.run_id != lease.run_id
            or job.worker_id != lease.worker_id
            or job.lease_token != lease.lease_token
            or job.lease_expires_at is None
            or job.lease_expires_at <= now
        ):
            raise SchedulerLeaseError("Job ownership is stale or expired")
        coordinator = self.db.fetchone(
            "SELECT * FROM orchestration_scheduler_coordinator WHERE singleton=1"
        )
        if (
            not coordinator
            or coordinator["owner_id"] != job.coordinator_owner_id
            or coordinator["lease_token"] != job.coordinator_token
            or lease.coordinator_owner_id != job.coordinator_owner_id
            or lease.coordinator_token != job.coordinator_token
            or datetime.fromisoformat(coordinator["lease_expires_at"]) <= now
        ):
            raise SchedulerLeaseError("Job coordinator ownership is stale or expired")
        return job

    def heartbeat(
        self,
        lease: JobLease,
        lease_seconds: float = 30,
        *,
        allow_cancellation: bool = False,
    ) -> JobLease:
        """Renew ownership, optionally while a handler settles cancellation.

        The grace renewal prevents expired-lease recovery from replaying work
        while the current callback is still responding to cancellation.
        """
        seconds = _seconds(lease_seconds)
        if type(allow_cancellation) is not bool:
            raise ValueError("allow_cancellation must be a boolean")
        with self.db.transaction():
            now = self._now()
            job = self._owned(lease, now)
            if job.cancellation_requested and not allow_cancellation:
                raise SchedulerLeaseError("Cancellation requested")
            job = SchedulerJob.model_validate(
                job.model_dump()
                | {
                    "lease_expires_at": now + timedelta(seconds=seconds),
                    "heartbeat_at": now,
                    "updated_at": now,
                }
            )
            self._save_job(job)
            return self._lease(
                job,
                self.records.get_task(job.org_id, job.task_id),
                self.records.get_agent_run(job.org_id, cast("str", job.run_id)),
            )

    def is_cancel_requested(self, lease: JobLease) -> bool:
        with self.db.transaction():
            try:
                return self._owned(lease, self._now()).cancellation_requested
            except (SchedulerLeaseError, OrchestrationNotFoundError):
                return True

    def _hold(
        self, job: SchedulerJob, task: Task, now: datetime, reason: str
    ) -> SchedulerJob:
        self._save_record(
            Task.model_validate(
                task.model_dump()
                | {
                    "status": "waiting",
                    "updated_at": now,
                    "completed_at": None,
                }
            )
        )
        held = SchedulerJob.model_validate(
            job.model_dump()
            | {
                "status": "waiting",
                "updated_at": now,
                "recovery_reason": reason,
                "worker_id": None,
                "lease_token": None,
                "lease_expires_at": None,
            }
        )
        self._save_job(held)
        return held

    def _finish(
        self,
        job: SchedulerJob,
        now: datetime,
        *,
        result: JsonValue = None,
        error: str | None = None,
        retryable: bool = False,
        cancelled: bool = False,
    ) -> SchedulerJob:
        task = self.records.get_task(job.org_id, job.task_id)
        run = self.records.get_agent_run(job.org_id, cast("str", job.run_id))
        uncertain = self._uncertain(job.org_id, job.task_id)
        unsafe_replay = error is not None and self._previous_dispatch(
            job.org_id, job.task_id
        )
        cancelled = cancelled or job.cancellation_requested
        run_status = "cancelled" if cancelled else "failed" if error else "completed"
        run = AgentRun.model_validate(
            run.model_dump()
            | {
                "status": run_status,
                "result": result if run_status == "completed" else None,
                "error": error,
                "updated_at": now,
                "completed_at": now,
            }
        )
        self._save_record(run)
        if uncertain or unsafe_replay:
            updated = SchedulerJob.model_validate(job.model_dump() | {"error": error})
            return self._hold(
                updated,
                task,
                now,
                "Action outcome requires reconciliation"
                if uncertain
                else "Previous action dispatch prevents automatic replay",
            )
        status = (
            "cancelled"
            if cancelled
            else "retry_wait"
            if error and retryable and job.attempt < job.max_attempts
            else "failed"
            if error
            else "completed"
        )
        task_status = "waiting" if status == "retry_wait" else status
        self._save_record(
            Task.model_validate(
                task.model_dump()
                | {
                    "status": task_status,
                    "updated_at": now,
                    "completed_at": now if status in _TERMINAL else None,
                }
            )
        )
        updated = SchedulerJob.model_validate(
            job.model_dump()
            | {
                "status": status,
                "error": error,
                "updated_at": now,
                "available_at": now
                + timedelta(seconds=min(300, 5 * 2 ** (job.attempt - 1)))
                if status == "retry_wait"
                else job.available_at,
                "worker_id": None,
                "lease_token": None,
                "lease_expires_at": None,
            }
        )
        self._save_job(updated)
        return updated

    def complete(self, lease: JobLease, result: JsonValue) -> SchedulerJob:
        with self.db.transaction():
            now = self._now()
            job = self._owned(lease, now)
            # Validate even if cancellation won; malformed handler outputs never persist.
            run = self.records.get_agent_run(job.org_id, lease.run_id)
            candidate = AgentRun.model_validate(run.model_dump() | {"result": result})
            _bounded_payload(candidate)
            return self._finish(job, now, result=result)

    def fail(
        self, lease: JobLease, error: str, *, retryable: bool = True
    ) -> SchedulerJob:
        if type(retryable) is not bool:
            raise ValueError("retryable must be a boolean")
        with self.db.transaction():
            now = self._now()
            job = self._owned(lease, now)
            run = self.records.get_agent_run(job.org_id, lease.run_id)
            AgentRun.model_validate(run.model_dump() | {"error": error})
            return self._finish(job, now, error=error, retryable=retryable)

    def cancel(self, lease: JobLease) -> SchedulerJob:
        with self.db.transaction():
            now = self._now()
            return self._finish(self._owned(lease, now), now, cancelled=True)

    def hold(self, lease: JobLease, reason: str) -> SchedulerJob:
        """Fence noncooperative execution and require manual reconciliation."""
        with self.db.transaction():
            now = self._now()
            job = self._owned(lease, now)
            run = self.records.get_agent_run(job.org_id, lease.run_id)
            run = AgentRun.model_validate(
                run.model_dump()
                | {
                    "status": "failed",
                    "error": reason,
                    "completed_at": now,
                    "updated_at": now,
                }
            )
            self._save_record(run)
            job = SchedulerJob.model_validate(job.model_dump() | {"error": reason})
            return self._hold(
                job, self.records.get_task(job.org_id, job.task_id), now, reason
            )

    def request_cancel(self, org_id: str, task_id: str) -> SchedulerJob:
        with self.db.transaction():
            job = self.get_job(org_id, task_id)
            if job.status in _TERMINAL:
                return job
            now = self._now()
            job = SchedulerJob.model_validate(
                job.model_dump()
                | {
                    "cancellation_requested": True,
                    "updated_at": now,
                }
            )
            if job.status == "running":
                self._save_job(job)
                return job
            task = self.records.get_task(org_id, task_id)
            if job.status == "waiting" or self._uncertain(org_id, task_id):
                return self._hold(
                    job, task, now, "Cancellation awaits action reconciliation"
                )
            self._save_record(
                Task.model_validate(
                    task.model_dump()
                    | {
                        "status": "cancelled",
                        "updated_at": now,
                        "completed_at": now,
                    }
                )
            )
            job = SchedulerJob.model_validate(
                job.model_dump() | {"status": "cancelled"}
            )
            self._save_job(job)
            return job

    def recover_expired(self, owner_id: str) -> list[SchedulerJob]:
        with self.db.transaction():
            now = self._now()
            self._require_coordinator(owner_id, now)
            rows = self.db.fetchall(
                "SELECT payload_json FROM orchestration_scheduler_jobs "
                "WHERE status='running' AND lease_expires_at<=? ORDER BY sequence",
                (_sql_time(now),),
            )
            recovered = []
            for row in rows:
                job = self._decode(row)
                reason = "Worker lease expired; previous execution fenced"
                job = SchedulerJob.model_validate(
                    job.model_dump() | {"recovery_reason": reason}
                )
                recovered.append(self._finish(job, now, error=reason, retryable=True))
            return recovered
