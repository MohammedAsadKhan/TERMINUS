"""FastAPI route handlers for Auth, Organization, License management, and Wazuh webhooks."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from terminus.auth.models import PublicUser, User
from terminus.auth.service import AuthService, DuplicateEmailError
from terminus.core.ids import OrgId, SessionToken, UserId
from terminus.licensing.crypto import LicenseError
from terminus.models import (
    AgentStatus,
    DailyIncidentReport,
    InvestigationReport,
    ReportType,
    SiemAlert,
    SocAgent,
    Workflow,
)
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.service import ForbiddenError, OrganizationService, SeatLimitError
from terminus.pipeline.runner import PipelineRunner
from terminus.reports.service import generate_daily_report
from terminus.server.deps import (
    get_auth_service,
    get_current_org,
    get_current_user,
    get_org_service,
    get_pipeline_runner,
    get_reports_store,
    get_tenant_agents,
    get_tenant_workflows,
    get_webhook_org,
    require_admin,
    require_operator,
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
    user: PublicUser


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



@health_router.get("/", include_in_schema=False)
@health_router.get("/dashboard", include_in_schema=False)
async def dashboard() -> RedirectResponse:
    return RedirectResponse("/console/")


@health_router.get("/console", include_in_schema=False)
async def console_redirect() -> RedirectResponse:
    return RedirectResponse("/console/")


@health_router.get("/console/", response_class=HTMLResponse, include_in_schema=False)
@health_router.get("/console/{path:path}", response_class=HTMLResponse, include_in_schema=False)
async def console_entry(path: str = "") -> HTMLResponse:
    entry = Path(__file__).parent / "static" / "console" / "index.html"
    if not entry.exists():
        return HTMLResponse("<h1>Build the Terminus console</h1><p>Run <code>cd web &amp;&amp; npm ci &amp;&amp; npm run build</code>, then refresh.</p>", status_code=503)
    return HTMLResponse(entry.read_text(encoding="utf-8"), headers={"Cache-Control": "no-cache"})


@health_router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "terminus"}


@auth_router.post("/register", status_code=status.HTTP_201_CREATED, response_model=PublicUser)
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
    response: Response,
    request: Request,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> LoginResponse:
    """Authenticate with email and password to receive a session token."""
    try:
        token = auth_service.login(email=req.email, password=req.password)
        user = auth_service.verify(token)
        response.set_cookie("terminus_session", token, httponly=True, secure=request.url.scheme == "https", samesite="strict", max_age=43200)
        return LoginResponse(session_token=token, user=PublicUser.model_validate(user))
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(err),
        ) from err


@auth_router.post("/logout")
async def logout(
    request: Request,
    response: Response,
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
    cookie = request.cookies.get("terminus_session")
    if cookie:
        auth_service.logout(SessionToken(cookie))
    response.delete_cookie("terminus_session")
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
) -> Any:
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


@webhook_router.post("/wazuh", dependencies=[Depends(require_operator)])
async def wazuh_webhook(
    alert: SiemAlert,
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> InvestigationReport:
    """Ingest Wazuh alert, execute pipeline investigation, create ticket, notify."""
    report = await pipeline_runner.process_alert(alert, org_id)
    return report


@webhook_router.get("/incidents")
async def list_incidents(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> list[dict[str, Any]]:
    """Fetch live incident tickets for the active tenant."""
    return await pipeline_runner.deployment.ticket_store.list_tickets(org_id)


class IncidentActionRequest(BaseModel):
    action_type: Literal["close_ticket", "reopen_ticket", "start_investigation", "isolate_host", "block_ip", "run_playbook"] = Field(description="Action to execute: isolate_host, block_ip, run_playbook, close_ticket")


@webhook_router.post("/incidents/{ticket_id}/action", dependencies=[Depends(require_operator)])
async def execute_incident_action(
    ticket_id: str,
    req: IncidentActionRequest,
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> dict[str, Any]:
    """Execute 1-click inline containment response on an incident."""
    ticket_store = pipeline_runner.deployment.ticket_store
    ticket = await ticket_store.get_ticket(ticket_id, org_id)

    from datetime import UTC, datetime
    statuses = {"close_ticket": "RESOLVED", "reopen_ticket": "OPEN", "start_investigation": "INVESTIGATING"}
    if req.action_type not in statuses:
        raise HTTPException(501, "Live containment requires a verified response connector. No external action was executed.")
    ticket["status"] = statuses[req.action_type]
    ticket["updated_at"] = datetime.now(UTC).isoformat()
    ticket["resolved_at"] = ticket["updated_at"] if req.action_type == "close_ticket" else ""
    return {"status": "success", "ticket": ticket, "message": f"Incident marked {ticket['status'].lower()}"}


@webhook_router.get("/metrics/summary")
async def get_metrics_summary(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> dict[str, Any]:
    """Fetch decision-reduction SLA metrics (MTTD, MTTR, Signal-to-Noise Ratio)."""
    tickets = await pipeline_runner.deployment.ticket_store.list_tickets(org_id)
    return {
        "total_incidents_processed": len(tickets),
        "open_incidents": sum(t.get("status") != "RESOLVED" for t in tickets),
        "resolved_incidents": sum(t.get("status") == "RESOLVED" for t in tickets),
        "critical_incidents": sum(t.get("severity") == "critical" and t.get("status") != "RESOLVED" for t in tickets),
        "mttd_seconds": None, "mttr_seconds": None, "signal_to_noise_pct": None,
        "auto_containment_rate_pct": None,
    }


# ─── Agents & Workflow Routers ───────────────────────────────────────────────────

agent_router = APIRouter(prefix="/agents", tags=["Agents"])
workflow_router = APIRouter(prefix="/workflows", tags=["Workflows"])




class CreateAgentRequest(BaseModel):
    name: str = Field(min_length=1)
    role_description: str = Field(min_length=1)
    master_prompt: str = Field(min_length=1)


class UpdateAgentRequest(BaseModel):
    name: str | None = None
    role_description: str | None = None
    master_prompt: str | None = None
    status: AgentStatus | None = None


@agent_router.get("")
async def list_agents(
    agents_store: Annotated[dict[str, SocAgent], Depends(get_tenant_agents)],
) -> list[SocAgent]:
    """List all AI SOC agents in the active fleet."""
    return list(agents_store.values())


@agent_router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def create_agent(
    req: CreateAgentRequest,
    agents_store: Annotated[dict[str, SocAgent], Depends(get_tenant_agents)],
) -> SocAgent:
    """Deploy a new AI SOC agent with custom master system prompt."""
    import secrets
    from datetime import datetime

    agent_id = f"agent-{secrets.token_hex(4)}"
    new_agent = SocAgent(
        id=agent_id,
        name=req.name,
        role_description=req.role_description,
        master_prompt=req.master_prompt,
        status=AgentStatus.ACTIVE,
        incidents_processed=0,
        avg_sla_ms=0.0,
        created_at=datetime.now(UTC).isoformat(),
    )
    agents_store[agent_id] = new_agent
    return new_agent


@agent_router.patch("/{agent_id}", dependencies=[Depends(require_admin)])
async def update_agent(
    agent_id: str,
    req: UpdateAgentRequest,
    agents_store: Annotated[dict[str, SocAgent], Depends(get_tenant_agents)],
) -> SocAgent:
    """Update agent status (ON/OFF toggle) or master system prompt."""
    agent = agents_store.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")

    updated_data = agent.model_dump()
    if req.name is not None:
        updated_data["name"] = req.name
    if req.role_description is not None:
        updated_data["role_description"] = req.role_description
    if req.master_prompt is not None:
        updated_data["master_prompt"] = req.master_prompt
    if req.status is not None:
        updated_data["status"] = req.status

    updated_agent = SocAgent(**updated_data)
    agents_store[agent_id] = updated_agent
    return updated_agent


@workflow_router.get("")
async def list_workflows(
    workflows_store: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)],
) -> list[Workflow]:
    """List all n8n-style visual SOC workflows."""
    return list(workflows_store.values())


@workflow_router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def create_workflow(
    workflow: Workflow,
    workflows_store: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)],
) -> Workflow:
    """Create a new visual node workflow."""
    from terminus.server.console_api import workflow_errors
    if workflow.id in workflows_store:
        raise HTTPException(409, "Workflow ID already exists")
    errors = workflow_errors(workflow)
    if errors:
        raise HTTPException(422, "; ".join(errors))
    workflows_store[workflow.id] = workflow
    return workflow


@workflow_router.put("/{workflow_id}", dependencies=[Depends(require_admin)])
async def update_workflow(
    workflow_id: str,
    workflow: Workflow,
    workflows_store: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)],
) -> Workflow:
    """Save/update node layout, connections, and node configs for a workflow."""
    from terminus.server.console_api import workflow_errors
    if workflow_id not in workflows_store:
        raise HTTPException(404, "Workflow not found")
    if workflow.id != workflow_id:
        raise HTTPException(422, "Workflow IDs must match")
    errors = workflow_errors(workflow)
    if errors:
        raise HTTPException(422, "; ".join(errors))
    workflows_store[workflow_id] = workflow
    return workflow


@workflow_router.post("/{workflow_id}/execute", dependencies=[Depends(require_operator)])
async def execute_test_workflow(
    workflow_id: str,
    workflows_store: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)],
    agents_store: Annotated[dict[str, SocAgent], Depends(get_tenant_agents)],
) -> dict[str, Any]:
    """Simulate a test execution run of a node workflow."""
    wf = workflows_store.get(workflow_id)
    if not wf:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found")

    from terminus.server.console_api import workflow_errors
    errors = workflow_errors(wf)
    return {
        "status": "invalid" if errors else "validated", "mode": "validation_only",
        "workflow_id": workflow_id, "nodes_validated": len(wf.nodes), "nodes_executed": 0,
        "errors": errors,
        "summary": "Definition validation only. No nodes or external actions were executed.",
    }


# ─── Report Manager Router ──────────────────────────────────────────────────────────

report_router = APIRouter(prefix="/reports", tags=["Reports"])



@report_router.post("/quick", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_operator)])
async def generate_quick_report(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    reports_store: Annotated[dict[str, dict[str, DailyIncidentReport]], Depends(get_reports_store)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> DailyIncidentReport:
    """Generate a Quick Report based on all logs from the start of the current day to now."""
    ticket_store = pipeline_runner.deployment.ticket_store
    report = await generate_daily_report(org_id, ReportType.QUICK, ticket_store)
    if org_id not in reports_store:
        reports_store[org_id] = {}
    reports_store[org_id][report.id] = report
    return report


@report_router.post("/daily", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_operator)])
async def generate_24h_report(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    reports_store: Annotated[dict[str, dict[str, DailyIncidentReport]], Depends(get_reports_store)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> DailyIncidentReport:
    """Generate a 24-Hour Daily Operations Summary Report."""
    ticket_store = pipeline_runner.deployment.ticket_store
    report = await generate_daily_report(org_id, ReportType.DAILY_24H, ticket_store)
    if org_id not in reports_store:
        reports_store[org_id] = {}
    reports_store[org_id][report.id] = report
    return report


@report_router.get("")
async def list_reports(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    reports_store: Annotated[dict[str, dict[str, DailyIncidentReport]], Depends(get_reports_store)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> list[DailyIncidentReport]:
    """List all daily and quick incident reports for the active tenant."""
    org_reports = reports_store.get(org_id, {})
    return sorted(org_reports.values(), key=lambda r: r.created_at, reverse=True)


@report_router.get("/{report_id}")
async def get_report(
    report_id: str,
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    reports_store: Annotated[dict[str, dict[str, DailyIncidentReport]], Depends(get_reports_store)],
) -> DailyIncidentReport:
    """Fetch details for a specific daily incident report."""
    org_reports = reports_store.get(org_id, {})
    report = org_reports.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found")
    return report

