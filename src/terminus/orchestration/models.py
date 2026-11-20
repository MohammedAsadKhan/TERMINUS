# File name: models.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Strict durable records for orchestration; these records do not execute work.

"""Strict durable records for orchestration; these records do not execute work."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, ClassVar, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=r"\S")]
Label = Annotated[str, Field(min_length=1, max_length=120, pattern=r"\S")]
Text = Annotated[str, Field(min_length=1, max_length=16000, pattern=r"\S")]
TaskStatus = Literal["queued", "running", "waiting", "completed", "failed", "cancelled"]
RunStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
HelpStatus = Literal["open", "assigned", "resolved", "cancelled"]
ActionStatus = Literal[
    "proposed",
    "approved",
    "dispatched",
    "acknowledged",
    "verified",
    "failed",
    "unknown",
    "rejected",
]


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def new_id() -> str:
    """Return a new random UUID4 string for use as a record identifier."""
    return str(uuid4())


class DurableRecord(BaseModel):
    # Immutable, strictly validated base for persisted orchestration records, always
    # scoped by
    # org_id and incident_id so storage can enforce tenant isolation.

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )

    org_id: Identifier
    incident_id: Identifier
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator(
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "source_timestamp",
        "collected_at",
        "timestamp",
        check_fields=False,
    )
    @classmethod
    def utc_timestamp(cls, value: datetime | None) -> datetime | None:
        """Reject naive datetimes and normalize aware ones to UTC so stored times compare
        consistently.
        """
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)


class Task(DurableRecord):
    # A unit of delegated incident work (area, role, objective) with a lifecycle status;
    # an
    # optional idempotency_key lets a repeated create return the same task.

    task_id: Identifier = Field(default_factory=new_id)
    parent_task_id: Identifier | None = None
    area: Label
    role: Label
    objective: Text
    status: TaskStatus = "queued"
    priority: Annotated[int, Field(ge=0, le=1000)] = 100
    idempotency_key: Identifier | None = None
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AgentRun(DurableRecord):
    # One execution of a task by an agent, recording the model connection used and the
    # eventual
    # result or error.

    run_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    agent_id: Identifier | None = None
    model_connection_id: Identifier | None = None
    model_name: Label | None = None
    status: RunStatus = "queued"
    updated_at: datetime = Field(default_factory=utc_now)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: JsonValue = None
    error: Text | None = None


class EvidenceRecord(DurableRecord):
    # Evidence collected for a task, stored inline or by reference with a 64-character
    # hexadecimal
    # content hash.

    evidence_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    source: Label
    source_timestamp: datetime
    collected_at: datetime = Field(default_factory=utc_now)
    content: JsonValue = None
    content_ref: Annotated[str, Field(min_length=1, max_length=2000)] | None = None
    content_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @model_validator(mode="after")
    def require_content(self) -> EvidenceRecord:
        """Reject evidence that carries neither inline content nor a content reference."""
        if self.content is None and self.content_ref is None:
            raise ValueError("evidence requires content or a content reference")
        return self


class HelpRequest(DurableRecord):
    # A request for another specialist role to assist with a task, from open to resolved
    # or
    # cancelled.

    help_request_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    requested_role: Label
    reason: Text
    status: HelpStatus = "open"
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class ActionAttempt(DurableRecord):
    # A response action proposed against one to 100 targets for a task; its status
    # follows the
    # lifecycle enforced in storage.py.

    attempt_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    action: Label
    targets: Annotated[list[Identifier], Field(min_length=1, max_length=100)]
    status: ActionStatus = "proposed"
    inputs: dict[str, JsonValue] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class ActionAttemptEvent(DurableRecord):
    # Immutable history entry recording each status change of an ActionAttempt and who
    # made it.

    event_id: Identifier = Field(default_factory=new_id)
    attempt_id: Identifier
    status: ActionStatus
    timestamp: datetime = Field(default_factory=utc_now)
    actor: Identifier
    outputs: dict[str, JsonValue] = Field(default_factory=dict)
    error: Text | None = None
