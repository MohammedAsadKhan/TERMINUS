"""Strict scheduler metadata and fencing tokens, separate from canonical tasks."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, field_validator

from terminus.orchestration.models import (
    AgentRun,
    DurableRecord,
    Identifier,
    Label,
    Task,
    Text,
    new_id,
)

JobStatus = Literal[
    "queued", "running", "retry_wait", "waiting", "completed", "failed", "cancelled"
]


class SchedulerJob(DurableRecord):
    job_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    role: Label
    priority: Annotated[int, Field(ge=0, le=1000)]
    status: JobStatus = "queued"
    attempt: Annotated[int, Field(ge=0, le=5)] = 0
    max_attempts: Annotated[int, Field(ge=1, le=5)] = 3
    available_at: datetime
    updated_at: datetime
    worker_id: Identifier | None = None
    lease_token: Identifier | None = None
    lease_expires_at: datetime | None = None
    heartbeat_at: datetime | None = None
    run_id: Identifier | None = None
    coordinator_owner_id: Identifier | None = None
    coordinator_token: Identifier | None = None
    cancellation_requested: bool = False
    error: Text | None = None
    recovery_reason: Text | None = None

    @field_validator("available_at", "lease_expires_at", "heartbeat_at")
    @classmethod
    def normalize_time(cls, value: datetime | None) -> datetime | None:
        return cls.utc_timestamp(value)


class JobLease(DurableRecord):
    job_id: Identifier
    task_id: Identifier
    run_id: Identifier
    worker_id: Identifier
    lease_token: Identifier
    coordinator_owner_id: Identifier
    coordinator_token: Identifier
    lease_expires_at: datetime
    attempt: Annotated[int, Field(ge=1, le=5)]
    task: Task
    run: AgentRun

    @field_validator("lease_expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return cls.utc_timestamp(value)


class CoordinatorLease(DurableRecord):
    # The singleton is global. Scope fields deliberately carry fixed values.
    org_id: Identifier = "scheduler"
    incident_id: Identifier = "coordinator"
    owner_id: Identifier
    lease_token: Identifier
    lease_expires_at: datetime

    @field_validator("lease_expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return cls.utc_timestamp(value)
