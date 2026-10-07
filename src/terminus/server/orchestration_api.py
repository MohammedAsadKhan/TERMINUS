"""Authenticated inspection and control endpoints for durable orchestration."""

from __future__ import annotations

import re
from typing import Annotated, Any, cast

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from terminus.core.ids import OrgId
from terminus.orchestration import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
    OrchestrationTransitionError,
    Task,
)
from terminus.orchestration.scheduler_models import SchedulerJob
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.privacy.redactor import SecretRedactor
from terminus.server.deps import get_current_org, require_operator
from terminus.storage.db import Database

router = APIRouter(prefix="/orchestration", tags=["orchestration"])
CurrentOrg = Annotated[OrgId, Depends(get_current_org)]


def get_orchestration_store() -> OrchestrationStore:
    return OrchestrationStore(Database.get_instance())


def get_scheduler_store() -> SchedulerStore:
    return SchedulerStore(Database.get_instance())


class EnqueueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    max_attempts: int = Field(default=3, ge=1, le=5)


_SECRET_KEY = re.compile(r"(?:secret|token|password|credential|api[_-]?key|authorization)", re.IGNORECASE)
_PUBLIC_USAGE_FIELDS = {
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "cached_input_tokens",
    "reasoning_tokens",
}


def _public_usage_count(key: object, value: JsonValue) -> bool:
    """Allow bounded numeric usage metadata without weakening credential redaction."""
    return (
        key in _PUBLIC_USAGE_FIELDS
        and (value is None or (type(value) is int and 0 <= value <= 1_000_000_000))
    )


def _redact(value: JsonValue) -> JsonValue:
    """Remove credential-shaped metadata before returning durable JSON fields."""
    if isinstance(value, dict):
        return {
            key: (
                item if _public_usage_count(key, item)
                else "[redacted]" if _SECRET_KEY.search(str(key))
                else "Execution error; inspect protected diagnostics" if key == "error" and item
                else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        return SecretRedactor.redact(value)
    return value


def _record(record: BaseModel) -> dict[str, Any]:
    return cast(dict[str, Any], _redact(record.model_dump(mode="json")))


_PUBLIC_JOB_FIELDS = (
    "job_id",
    "org_id",
    "incident_id",
    "task_id",
    "role",
    "priority",
    "status",
    "attempt",
    "max_attempts",
    "available_at",
    "created_at",
    "updated_at",
    "worker_id",
    "lease_expires_at",
    "heartbeat_at",
    "run_id",
    "cancellation_requested",
    "error",
    "recovery_reason",
)


def _public_job(job: SchedulerJob | None) -> dict[str, Any] | None:
    if job is None:
        return None
    values = job.model_dump(mode="json", include=set(_PUBLIC_JOB_FIELDS))
    return cast(dict[str, Any], _redact(values))


def _get_job(store: SchedulerStore, org_id: str, task_id: str) -> SchedulerJob | None:
    try:
        return store.get_job(org_id, task_id)
    except OrchestrationNotFoundError:
        return None


def _handle_store_error(exc: Exception) -> HTTPException:
    if isinstance(exc, OrchestrationNotFoundError):
        return HTTPException(status_code=404, detail="Orchestration record not found")
    if isinstance(exc, (OrchestrationConflictError, OrchestrationTransitionError)):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, (ValidationError, ValueError, TypeError)):
        return HTTPException(status_code=400, detail=str(exc))
    raise exc


def _parse_enqueue_payload(payload: dict[str, Any]) -> EnqueueRequest:
    try:
        return EnqueueRequest.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.errors(include_input=False)) from exc


def _validate_paging(limit: int, offset: int) -> None:
    if not 1 <= limit <= 200 or offset < 0:
        raise HTTPException(status_code=400, detail="limit must be 1..200 and offset nonnegative")


def _detail(org_id: str, task: Task, store: OrchestrationStore, scheduler: SchedulerStore) -> dict[str, Any]:
    task_id = task.task_id
    runs = store.list_agent_runs(org_id, task_id=task_id, limit=200)
    evidence = store.list_evidence(org_id, task_id=task_id, limit=200)
    help_requests = store.list_help_requests(org_id, task_id=task_id, limit=200)
    actions = store.list_action_attempts(org_id, task_id=task_id, limit=200)
    return {
        "task": _record(task),
        "scheduler_job": _public_job(_get_job(scheduler, org_id, task_id)),
        "runs": [_record(item) for item in runs],
        "evidence": [_record(item) for item in evidence],
        "help_requests": [_record(item) for item in help_requests],
        "actions": [_record(item) for item in actions],
        "child_records_limit": 200,
        "child_records_may_be_truncated": any(
            len(items) == 200 for items in (runs, evidence, help_requests, actions)
        ),
    }


@router.get("/tasks")
def list_tasks(
    org_id: CurrentOrg,
    store: Annotated[OrchestrationStore, Depends(get_orchestration_store)],
    scheduler: Annotated[SchedulerStore, Depends(get_scheduler_store)],
    limit: Annotated[int, Query()] = 50,
    offset: Annotated[int, Query()] = 0,
    incident_id: str | None = None,
    task_status: Annotated[str | None, Query(alias="status")] = None,
    newest_first: bool = False,
) -> dict[str, Any]:
    _validate_paging(limit, offset)
    try:
        tasks = store.list_tasks(str(org_id), incident_id=incident_id, status=task_status, limit=limit, offset=offset, newest_first=newest_first)
        return {
            "items": [
                {
                    "task": _record(task),
                    "scheduler_job": _public_job(_get_job(scheduler, str(org_id), task.task_id)),
                }
                for task in tasks
            ],
            "limit": limit,
            "offset": offset,
        }
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.get("/tasks/{task_id}")
def get_task(
    task_id: str,
    org_id: CurrentOrg,
    store: Annotated[OrchestrationStore, Depends(get_orchestration_store)],
    scheduler: Annotated[SchedulerStore, Depends(get_scheduler_store)],
) -> dict[str, Any]:
    try:
        task = store.get_task(str(org_id), task_id)
        return _detail(str(org_id), task, store, scheduler)
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.post("/tasks/{task_id}/enqueue", status_code=status.HTTP_202_ACCEPTED)
def enqueue_task(
    task_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    scheduler: Annotated[SchedulerStore, Depends(get_scheduler_store)],
    payload: Annotated[dict[str, Any] | None, Body()] = None,
) -> dict[str, Any]:
    request = _parse_enqueue_payload(payload or {})
    try:
        job = scheduler.enqueue_task(str(org_id), task_id, max_attempts=request.max_attempts)
        return _public_job(job) or {}
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.post("/tasks/{task_id}/cancel")
def cancel_task(
    task_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    scheduler: Annotated[SchedulerStore, Depends(get_scheduler_store)],
) -> dict[str, Any]:
    try:
        job = scheduler.request_cancel(str(org_id), task_id)
        return _public_job(job) or {}
    except Exception as exc:
        raise _handle_store_error(exc) from exc
