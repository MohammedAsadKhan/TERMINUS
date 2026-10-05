"""Authenticated, tenant-scoped coordination controls and persisted inspection."""

from __future__ import annotations

from typing import Annotated, Any, cast

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import ValidationError

from terminus.core.ids import OrgId
from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.coordination_models import (
    HelpRequestSpec,
    IncidentObjective,
)
from terminus.server.deps import get_current_org, require_operator
from terminus.server.orchestration_api import _handle_store_error, _record, _redact
from terminus.storage.db import Database

router = APIRouter(prefix="/orchestration", tags=["coordination"])
CurrentOrg = Annotated[OrgId, Depends(get_current_org)]


def get_coordination_service() -> CoordinationService:
    return CoordinationService(Database.get_instance())


@router.post("/incidents/{incident_id}/start", status_code=status.HTTP_202_ACCEPTED)
def start_incident(
    incident_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
    payload: Annotated[dict[str, Any], Body()],
) -> dict[str, Any]:
    try:
        request = IncidentObjective.model_validate(payload)
    except ValidationError as exc:
        # Do not echo credentials or arbitrary attacker-supplied input in errors.
        raise HTTPException(status_code=400, detail="Invalid incident objective") from exc
    try:
        return _record(service.start_incident(str(org_id), incident_id, request))
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.get("/incidents/{incident_id}/tree")
def get_incident_tree(
    incident_id: str,
    org_id: CurrentOrg,
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
) -> dict[str, Any]:
    try:
        return cast(dict[str, Any], _redact(service.get_incident_tree(str(org_id), incident_id)))
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.post("/help-requests/{help_request_id}/assign", status_code=status.HTTP_202_ACCEPTED)
def assign_help(
    help_request_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
) -> dict[str, Any]:
    try:
        return _record(service.assign_help(str(org_id), help_request_id))
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.post("/help-requests/{help_request_id}/reconcile")
def reconcile_help(
    help_request_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
) -> dict[str, Any]:
    try:
        request = service.reconcile_help(str(org_id), help_request_id)
        return cast(
            dict[str, Any],
            _redact(
                {
                    **_record(request),
                    "ownership": service.collaboration.ownership(
                        str(org_id), help_request_id
                    ),
                }
            ),
        )
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.post("/tasks/{task_id}/help-requests", status_code=status.HTTP_202_ACCEPTED)
def request_help(
    task_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
    payload: Annotated[dict[str, Any], Body()],
) -> dict[str, Any]:
    try:
        spec = HelpRequestSpec.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="Invalid help request") from exc
    try:
        return cast(
            dict[str, Any],
            _redact(service.request_help(str(org_id), task_id, spec)),
        )
    except Exception as exc:
        raise _handle_store_error(exc) from exc


@router.get("/tasks/{task_id}/help-context")
def get_help_context(
    task_id: str,
    org_id: CurrentOrg,
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
) -> dict[str, Any]:
    try:
        return cast(
            dict[str, Any], _redact(service.get_help_context(str(org_id), task_id))
        )
    except Exception as exc:
        raise _handle_store_error(exc) from exc
