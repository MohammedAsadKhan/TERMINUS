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
    return datetime.now(UTC)


def new_id() -> str:
    return str(uuid4())


class DurableRecord(BaseModel):
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
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return value.astimezone(UTC)


class Task(DurableRecord):
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
        if self.content is None and self.content_ref is None:
            raise ValueError("evidence requires content or a content reference")
        return self


class HelpRequest(DurableRecord):
    help_request_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    requested_role: Label
    reason: Text
    status: HelpStatus = "open"
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class ActionAttempt(DurableRecord):
    attempt_id: Identifier = Field(default_factory=new_id)
    task_id: Identifier
    action: Label
    targets: Annotated[list[Identifier], Field(min_length=1, max_length=100)]
    status: ActionStatus = "proposed"
    inputs: dict[str, JsonValue] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class ActionAttemptEvent(DurableRecord):
    event_id: Identifier = Field(default_factory=new_id)
    attempt_id: Identifier
    status: ActionStatus
    timestamp: datetime = Field(default_factory=utc_now)
    actor: Identifier
    outputs: dict[str, JsonValue] = Field(default_factory=dict)
    error: Text | None = None
