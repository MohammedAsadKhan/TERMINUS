# File name: response_api.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Tenant-scoped operator response decisions; no browser-supplied commands.

"""Tenant-scoped operator response decisions; no browser-supplied commands."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from terminus.auth.models import User
from terminus.core.ids import OrgId
from terminus.response.live import LiveResponseService, ResponseConflictError
from terminus.server.deps import get_current_org, get_current_user
from terminus.storage.db import Database

router = APIRouter(prefix="/incidents", tags=["live-response"])
Org = Annotated[OrgId, Depends(get_current_org)]
Actor = Annotated[User, Depends(get_current_user)]


class DecisionRequest(BaseModel):
    # Body for a response decision: the reviewed proposal digest (a 64-character hex
    # SHA-256), the decision, and an optional note.
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern="^[a-f0-9]{64}$")
    decision: Literal["approve", "autonomy", "reject", "defer"]
    note: str = Field(default="", max_length=2000)


def get_live_response_service() -> LiveResponseService:
    """FastAPI dependency building the live response service on the active database."""
    return LiveResponseService(Database.get_instance())


Service = Annotated[LiveResponseService, Depends(get_live_response_service)]


def handle(exc: Exception) -> HTTPException:
    """Map service errors to HTTP statuses: PermissionError 403, LookupError 404,
    ResponseConflictError 409, ValueError 400, and anything else a generic 500 that
    hides the cause.
    """
    if isinstance(exc, PermissionError):
        return HTTPException(403, str(exc))
    if isinstance(exc, LookupError):
        return HTTPException(404, str(exc))
    if isinstance(exc, ResponseConflictError):
        return HTTPException(409, str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(400, str(exc))
    return HTTPException(500, "Response operation failed")


@router.get("/{incident_id}/response")
def inspect(incident_id: str, org: Org, service: Service) -> dict:
    """Return the incident's response proposals, authorizations, intents, events and
    observations for the caller's organization; 404 if the incident is not found there.
    """
    try:
        return service.inspect(str(org), incident_id)
    except (ValueError, LookupError, PermissionError) as exc:
        raise handle(exc) from exc


@router.post("/{incident_id}/response/refresh")
def refresh(incident_id: str, org: Org, actor: Actor, service: Service) -> dict:
    """Admin-only: rebuild the system response recommendation from the incident's
    trusted evidence and return the updated response view.
    """
    try:
        service.require_admin(str(org), str(actor.user_id))
        service.refresh(str(org), incident_id)
        return service.inspect(str(org), incident_id)
    except (ValueError, LookupError, PermissionError) as exc:
        raise handle(exc) from exc


@router.post("/{incident_id}/response/{proposal_id}/decision", status_code=202)
def decide(
    incident_id: str,
    proposal_id: str,
    request: DecisionRequest,
    org: Org,
    actor: Actor,
    service: Service,
) -> dict:
    """Admin-only: record an approve, autonomy, reject or defer decision on the proposal
    whose digest the caller reviewed; returns 202, 409 if the proposal changed or was
    already decided, and 403 for a human author approving their own revision.
    """
    try:
        return service.decide(
            str(org),
            incident_id,
            proposal_id,
            str(actor.user_id),
            request.digest,
            request.decision,
            request.note,
        )
    except (ValueError, LookupError, PermissionError) as exc:
        raise handle(exc) from exc


@router.post("/{incident_id}/response/stop")
def stop(incident_id: str, org: Org, actor: Actor, service: Service) -> dict:
    """Admin-only: revoke the incident's active response authorizations; effects already
    applied still expire and are reconciled.
    """
    try:
        return service.stop(str(org), incident_id, str(actor.user_id))
    except (ValueError, LookupError, PermissionError) as exc:
        raise handle(exc) from exc


class RevisionRequest(BaseModel):
    # Body for revising a proposal: the reviewed digest and a new duration of 30 to 120
    # seconds.
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern="^[a-f0-9]{64}$")
    duration_seconds: int = Field(ge=30, le=120)


@router.post("/{incident_id}/response/{proposal_id}/revision", status_code=201)
def revise(
    incident_id: str,
    proposal_id: str,
    request: RevisionRequest,
    org: Org,
    actor: Actor,
    service: Service,
) -> dict:
    """Admin-only: create a human-authored revision of the proposal with a new duration;
    returns 201, and a different admin must approve the revision.
    """
    try:
        return service.revise(
            str(org),
            incident_id,
            proposal_id,
            str(actor.user_id),
            request.digest,
            request.duration_seconds,
        )
    except (ValueError, LookupError, PermissionError) as exc:
        raise handle(exc) from exc
