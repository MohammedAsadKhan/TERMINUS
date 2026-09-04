"""FastAPI route handlers for Auth, Organization, License management, and Wazuh webhooks."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from terminus.auth.models import User
from terminus.auth.service import AuthService, DuplicateEmailError
from terminus.core.ids import OrgId, SessionToken, UserId
from terminus.licensing.crypto import LicenseError
from terminus.models import InvestigationReport, SiemAlert
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.service import ForbiddenError, OrganizationService, SeatLimitError
from terminus.pipeline.runner import PipelineRunner
from terminus.server.deps import (
    get_auth_service,
    get_current_org,
    get_current_user,
    get_org_service,
    get_pipeline_runner,
    get_webhook_org,
    require_admin,
)

# ─── Request & Response Models ─────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str = Field(min_length=8)
    display_name: str = Field(min_length=1)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str
    password: str


class LoginResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_token: str
    user: User


class CreateOrgRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1)


class AddMemberRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: UserId
    role: OrganizationRole = OrganizationRole.MEMBER


class ActivateLicenseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str


# ─── Routers ───────────────────────────────────────────────────────────────────────

health_router = APIRouter(tags=["Health"])
auth_router = APIRouter(prefix="/auth", tags=["Auth"])
org_router = APIRouter(prefix="/orgs", tags=["Organizations"])
webhook_router = APIRouter(tags=["Webhooks"])


from pathlib import Path
from fastapi.responses import HTMLResponse

@health_router.get("/", response_class=HTMLResponse)
@health_router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve the interactive Terminus Analyst Command Center Dashboard."""
    dash_path = Path(__file__).parent / "static" / "dashboard.html"
    if dash_path.exists():
        content = dash_path.read_text(encoding="utf-8")
        return HTMLResponse(content=content)
    return HTMLResponse("<h1>Terminus Server Online</h1><p>Visit <a href='/docs'>/docs</a></p>")




@health_router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "terminus"}


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    req: RegisterRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> User:
    """Register a new user identity."""
    try:
        return auth_service.register(
            email=req.email,
            password=req.password,
            display_name=req.display_name,
        )
    except DuplicateEmailError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err


@auth_router.post("/login")
async def login(
    req: LoginRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """Authenticate with email and password to receive a session token."""
    try:
        token = auth_service.login(email=req.email, password=req.password)
        user = auth_service.verify(token)
        return LoginResponse(session_token=token, user=user)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(err),
        ) from err


@auth_router.post("/logout")
async def logout(
    user: Annotated[User, Depends(get_current_user)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    x_session_token: Annotated[str | None, Header(alias="X-Session-Token")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> dict[str, str]:
    """Revoke active session token."""
    token_str = x_session_token
    if not token_str and authorization:
        token_str = authorization.removeprefix("Bearer ")
    if token_str:
        auth_service.logout(SessionToken(token_str))
    return {"status": "logged_out"}


@org_router.post("", status_code=status.HTTP_201_CREATED)
async def create_org(
    req: CreateOrgRequest,
    user: Annotated[User, Depends(get_current_user)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> Organization:
    """Create a new organization (current user becomes Admin)."""
    return org_service.create_org(name=req.name, creator_id=user.user_id)


@org_router.get("")
async def list_user_orgs(
    user: Annotated[User, Depends(get_current_user)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> list[Organization]:
    """List all organizations that the current user belongs to."""
    return org_service.list_for_user(user.user_id)


@org_router.post("/{target_org_id}/members", status_code=status.HTTP_201_CREATED)
async def add_member(
    target_org_id: OrgId,
    req: AddMemberRequest,
    current_org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
    _: Annotated[None, Depends(require_admin)] = None,
) -> Membership:
    """Add a new member to the organization (requires Admin role)."""
    if target_org_id != current_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot manage members across organizations",
        )
    try:
        return org_service.add_member(
            org_id=target_org_id,
            user_id=req.user_id,
            role=req.role,
            actor_id=user.user_id,
        )
    except ForbiddenError as err:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(err),
        ) from err
    except SeatLimitError as err:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=str(err),
        ) from err


@org_router.post("/{target_org_id}/license")
async def activate_license(
    target_org_id: OrgId,
    req: ActivateLicenseRequest,
    current_org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
    _: Annotated[None, Depends(require_admin)] = None,
) -> Organization:
    """Activate or upgrade software license token (requires Admin role)."""
    if target_org_id != current_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot activate license for another organization",
        )
    try:
        return org_service.activate_license(
            org_id=target_org_id,
            token=req.token,
            actor_id=user.user_id,
        )
    except (ForbiddenError, LicenseError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        ) from err


@webhook_router.options("/wazuh")
async def wazuh_webhook_options() -> dict[str, str]:
    """CORS preflight handler for Wazuh webhook."""
    return {"status": "ok"}


@webhook_router.post("/wazuh")
async def wazuh_webhook(
    alert: SiemAlert,
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> InvestigationReport:
    """Ingest Wazuh alert, execute pipeline investigation, create ticket, notify."""
    return await pipeline_runner.process_alert(alert, org_id)


@webhook_router.get("/incidents")
async def list_incidents(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> list[dict[str, str]]:
    """Fetch live incident tickets for the active tenant."""
    return await pipeline_runner.deployment.ticket_store.list_tickets(org_id)
