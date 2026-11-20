# File name: coordination_api.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Authenticated, tenant-scoped coordination controls and persisted inspection.

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
    """FastAPI dependency building a coordination service on the active database."""
    return CoordinationService(Database.get_instance())


@router.post("/incidents/{incident_id}/start", status_code=status.HTTP_202_ACCEPTED)
def start_incident(
    incident_id: str,
    org_id: CurrentOrg,
    _: Annotated[None, Depends(require_operator)],
    service: Annotated[CoordinationService, Depends(get_coordination_service)],
    payload: Annotated[dict[str, Any], Body()],
) -> dict[str, Any]:
    """Operator-only: start coordinated work on an incident in the caller's organization
    from a validated objective; returns 400 for an invalid objective without echoing its
    content.
    """
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
    """Return the incident's task tree for the caller's organization with sensitive
    values redacted.
    """
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
    """Operator-only: assign a pending help request in the caller's organization and
    return its recorded state.
    """
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
    """Operator-only: reconcile an assigned help request, resolving it only once the
    delegated specialist has completed, and return its redacted state and ownership.
    """
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
    """Operator-only: raise a help request for a task in the caller's organization from
    a validated spec; returns 400 for an invalid spec.
    """
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
    """Return the redacted context available to whoever answers a task's help request,
    scoped to the caller's organization.
    """
    try:
        return cast(
            dict[str, Any], _redact(service.get_help_context(str(org_id), task_id))
        )
    except Exception as exc:
        raise _handle_store_error(exc) from exc
