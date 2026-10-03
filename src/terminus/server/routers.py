"""FastAPI route handlers for Auth, Organization, License management, Workflows, Agents, and Wazuh webhooks."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from terminus.auth.models import PublicUser, User
from terminus.auth.service import AuthService, DuplicateEmailError, UserStore
from terminus.core.base import ConflictError
from terminus.core.ids import OrgId, SessionToken, UserId
from terminus.licensing.crypto import LicenseError
from terminus.licensing.models import License
from terminus.models import (
    AgentStatus,
    Confidence,
    DailyIncidentReport,
    Evidence,
    InvestigationReport,
    PolicyResult,
    ReportType,
    Severity,
    SiemAlert,
    SocAgent,
    Tier,
    Verdict,
    Workflow,
)
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.service import ForbiddenError, OrganizationService, SeatLimitError
from terminus.pipeline.nodes.schemas import NODE_REGISTRY_METADATA
from terminus.pipeline.runner import PipelineRunner
from terminus.pipeline.validation import validate_workflow
from terminus.reports.service import generate_daily_report
from terminus.server.deps import (
    get_action_log_repo,
    get_agent_repo,
    get_allowlist_repo,
    get_approval_repo,
    get_auth_service,
    get_current_org,
    get_current_user,
    get_current_user_role,
    get_org_service,
    get_pipeline_runner,
    get_reports_store,
    get_user_store,
    get_webhook_org,
    get_workflow_repo,
    get_workflow_run_repo,
    require_admin,
    require_operator,
)
from terminus.storage.repositories import (
    SqliteActionLogRepository,
    SqliteAgentRepository,
    SqliteAllowlistRepository,
    SqliteApprovalRepository,
    SqliteWorkflowRepository,
    SqliteWorkflowRunRepository,
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


class CreateAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    role_description: str = Field(min_length=1, max_length=500)
    master_prompt: str = Field(min_length=1, max_length=4000)


class UpdateAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, max_length=80)
    role_description: str | None = Field(default=None, max_length=500)
    master_prompt: str | None = Field(default=None, max_length=4000)
    status: AgentStatus | None = None


class ToggleWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


class ResolveApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "reject"]


class CreateAllowlistRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["host", "ip", "subnet", "domain"]
    value: str
    note: str | None = None


class DryRunExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    sample_alert: SiemAlert | None = None
    dry_run: bool = True


from terminus.server.streaming import broadcaster
from terminus.service.sensor import service_sensor


class ServiceHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = "siem_emitter"
    status: Literal["connected", "disconnected", "active", "idle"] = "connected"
    metadata: dict[str, Any] = Field(default_factory=dict)


# ─── Routers ───────────────────────────────────────────────────────────────────────

health_router = APIRouter(tags=["Health & Service"])
auth_router = APIRouter(prefix="/auth", tags=["Auth"])
org_router = APIRouter(prefix="/orgs", tags=["Organizations"])
webhook_router = APIRouter(tags=["Webhooks"])
workflow_router = APIRouter(prefix="/workflows", tags=["Workflows"])
agent_router = APIRouter(prefix="/agents", tags=["Agents"])
allowlist_router = APIRouter(prefix="/containment/allowlist", tags=["Containment Allowlist"])


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


@health_router.get("/health/status")
@health_router.get("/service/status")
async def get_service_status() -> dict[str, Any]:
    """Return real-time service status, telemetry connection state, and runtime metrics."""
    return service_sensor.get_status()


@health_router.post("/service/heartbeat")
async def post_service_heartbeat(req: ServiceHeartbeatRequest) -> dict[str, Any]:
    """Register or refresh a heartbeat from an external telemetry or simulation service."""
    status_info = service_sensor.register_heartbeat(
        source=req.source,
        status=req.status,
        metadata=req.metadata,
    )
    await broadcaster.broadcast("service:status_changed", status_info)
    return status_info


@health_router.post("/service/autoconfig")
async def run_service_autoconfig(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
    allowlist_repo: Annotated[SqliteAllowlistRepository, Depends(get_allowlist_repo)],
) -> dict[str, Any]:
    """Dynamically auto-configure the baseline environment for the tenant organization."""
    result = service_sensor.auto_configure_baseline(
        org_id=str(org_id),
        agent_repo=agent_repo,
        workflow_repo=workflow_repo,
        allowlist_repo=allowlist_repo,
    )
    await broadcaster.broadcast_to_org(org_id, "service:autoconfigured", result)
    return result


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
    user_store: Annotated[UserStore, Depends(get_user_store)],
    _: Annotated[None, Depends(require_admin)] = None,
) -> Membership:
    """Add a new member to the organization (requires Admin role)."""
    if target_org_id != current_org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot manage members across organizations",
        )
    if user_store.get(req.user_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{req.user_id}' does not exist",
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
) -> License:
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
@webhook_router.options("/alert")
@webhook_router.options("/webhook/wazuh")
@webhook_router.options("/webhook/alert")
async def wazuh_webhook_options() -> dict[str, str]:
    """CORS preflight handler for Wazuh webhook."""
    return {"status": "ok"}


@webhook_router.post("/wazuh", dependencies=[Depends(require_operator)])
@webhook_router.post("/alert", dependencies=[Depends(require_operator)])
@webhook_router.post("/webhook/wazuh", dependencies=[Depends(require_operator)])
@webhook_router.post("/webhook/alert", dependencies=[Depends(require_operator)])
async def wazuh_webhook(
    alert: SiemAlert,
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> InvestigationReport:
    """Ingest Wazuh/SIEM alert, execute pipeline investigation, create ticket, notify."""
    service_sensor.record_telemetry_event(source="siem_webhook", alert_id=str(alert.id))
    return await pipeline_runner.process_alert(alert, org_id)


@webhook_router.get("/incidents")
async def list_incidents(
    org_id: Annotated[OrgId, Depends(get_webhook_org)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> list[dict[str, Any]]:
    """Fetch live incident tickets for the active tenant."""
    return await pipeline_runner.deployment.ticket_store.list_tickets(org_id)


class IncidentActionRequest(BaseModel):
    action_type: Literal["close_ticket", "reopen_ticket", "start_investigation", "isolate_host", "block_ip", "run_playbook"] = Field(description="Action to execute: isolate_host, block_ip, run_playbook, close_ticket")
    resolution_category: Literal["true_positive", "false_positive", "benign_activity", "inconclusive"] | None = None
    resolution_notes: str | None = Field(default=None, max_length=4000)


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

    statuses = {"close_ticket": "RESOLVED", "reopen_ticket": "OPEN", "start_investigation": "INVESTIGATING"}
    if req.action_type not in statuses:
        raise HTTPException(501, "Live containment requires a verified response connector. No external action was executed.")
    ticket["status"] = statuses[req.action_type]
    ticket["updated_at"] = datetime.now(UTC).isoformat()
    ticket["resolved_at"] = ticket["updated_at"] if req.action_type == "close_ticket" else ""
    if req.action_type == "close_ticket":
        ticket["resolution_category"] = req.resolution_category or "inconclusive"
        ticket["resolution_notes"] = (req.resolution_notes or "").strip()
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


# ─── Workflows Router ─────────────────────────────────────────────────────────────


@workflow_router.get("/node-registry")
async def get_node_registry() -> list[dict[str, Any]]:
    """Return the registry of available node types, default schemas, and handles (D1, D8)."""
    return NODE_REGISTRY_METADATA


@workflow_router.get("/runs")
async def list_workflow_runs(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    run_repo: Annotated[SqliteWorkflowRunRepository, Depends(get_workflow_run_repo)],
    limit: int = 50,
) -> list[dict[str, Any]]:
    """List execution history of workflow runs for the active tenant."""
    return run_repo.list_runs_for_org(str(org_id), limit=limit)


@workflow_router.get("/runs/{run_id}")
async def get_workflow_run_detail(
    run_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    run_repo: Annotated[SqliteWorkflowRunRepository, Depends(get_workflow_run_repo)],
) -> dict[str, Any]:
    """Fetch workflow run summary and all individual node trace steps."""
    run = run_repo.get_run(str(org_id), run_id)
    if not run:
        raise HTTPException(status_code=404, detail=f"Workflow run '{run_id}' not found.")
    run["node_runs"] = run_repo.get_node_runs(str(org_id), run_id)
    return run


@workflow_router.get("/approvals/pending")
async def list_pending_approvals(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    approval_repo: Annotated[SqliteApprovalRepository, Depends(get_approval_repo)],
) -> list[dict[str, Any]]:
    """List pending human approval requests for the active tenant (D14)."""
    return approval_repo.list_pending(str(org_id))


@workflow_router.post("/approvals/{approval_id}/resolve")
async def resolve_workflow_approval(
    approval_id: str,
    req: ResolveApprovalRequest,
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user_role: Annotated[str, Depends(get_current_user_role)],
    approval_repo: Annotated[SqliteApprovalRepository, Depends(get_approval_repo)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> dict[str, Any]:
    """Approve or reject a pending workflow containment approval gate (D14)."""
    approval = approval_repo.get_approval(str(org_id), approval_id)
    if not approval or approval.get("status") != "PENDING":
        raise HTTPException(status_code=404, detail="Pending approval not found or already resolved.")

    if approval.get("required_role") == "admin" and user_role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required to resolve this approval.")

    new_status = "APPROVED" if req.decision == "approve" else "REJECTED"
    resolved_by = f"user:{user.display_name or user.email}"
    resolved = approval_repo.resolve_approval(str(org_id), approval_id, status=new_status, resolved_by=resolved_by)
    if not resolved:
        raise HTTPException(status_code=409, detail="Approval could not be updated.")

    run_ctx = await pipeline_runner.workflow_engine.resume_run(
        run_id=approval["run_id"],
        org_id=str(org_id),
        deployment=pipeline_runner.deployment,
        approver=resolved_by,
    )

    return {
        "status": "success",
        "approval_id": approval_id,
        "decision": req.decision,
        "run_id": approval["run_id"],
        "run_status": run_ctx.status if run_ctx else "COMPLETED",
    }


@workflow_router.get("")
async def list_workflows(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> list[Workflow]:
    """List all workflows for the active tenant ordered priority ASC, created_at ASC (D2)."""
    return workflow_repo.list_for_org(str(org_id))


@workflow_router.get("/{workflow_id}")
async def get_workflow(
    workflow_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> Workflow:
    """Fetch single workflow definition by ID."""
    wf = workflow_repo.get(workflow_id, str(org_id))
    if not wf:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")
    return wf


@workflow_router.post("", status_code=status.HTTP_201_CREATED)
async def create_workflow(
    workflow: Workflow,
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user_role: Annotated[str, Depends(get_current_user_role)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> Workflow:
    """Create a new visual SOC automation workflow."""
    if workflow_repo.get(workflow.id, str(org_id)):
        raise HTTPException(status_code=409, detail=f"Workflow with ID '{workflow.id}' already exists.")

    if user_role != "admin":
        workflow.enabled = False

    errors = validate_workflow(workflow, caller_role=user_role, is_enabling=workflow.enabled)
    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    return workflow_repo.save(workflow, str(org_id), created_by=str(user.user_id))


@workflow_router.put("/{workflow_id}")
async def update_workflow(
    workflow_id: str,
    workflow: Workflow,
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user_role: Annotated[str, Depends(get_current_user_role)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
    expected_version: int | None = None,
) -> Workflow:
    """Update workflow structure, node configurations, and connections (D18 concurrency)."""
    if workflow.id != workflow_id:
        raise HTTPException(status_code=422, detail="Workflow ID in body does not match path parameter.")

    existing = workflow_repo.get(workflow_id, str(org_id))
    if not existing:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")

    if user_role != "admin" and existing.enabled:
        structural_change = (
            [n.model_dump() for n in existing.nodes] != [n.model_dump() for n in workflow.nodes]
            or [e.model_dump() for e in existing.edges] != [e.model_dump() for e in workflow.edges]
            or existing.agent_id != workflow.agent_id
        )
        if structural_change:
            workflow.enabled = False

    errors = validate_workflow(workflow, caller_role=user_role, is_enabling=workflow.enabled)
    if errors:
        raise HTTPException(status_code=422, detail="; ".join(errors))

    target_version = expected_version or workflow.version or existing.version
    try:
        return workflow_repo.save(
            workflow,
            str(org_id),
            expected_version=target_version,
            created_by=str(user.user_id),
        )
    except ConflictError as err:
        raise HTTPException(status_code=409, detail=str(err)) from err


@workflow_router.patch("/{workflow_id}/enabled")
async def toggle_workflow_enabled(
    workflow_id: str,
    req: ToggleWorkflowRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user_role: Annotated[str, Depends(get_current_user_role)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> Workflow:
    """Enable or disable workflow execution (D13)."""
    existing = workflow_repo.get(workflow_id, str(org_id))
    if not existing:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")

    if req.enabled:
        errors = validate_workflow(existing, caller_role=user_role, is_enabling=True)
        if errors:
            raise HTTPException(status_code=422, detail="; ".join(errors))

    updated = workflow_repo.set_enabled(workflow_id, str(org_id), req.enabled)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Failed to toggle workflow '{workflow_id}'.")
    return updated


@workflow_router.delete("/{workflow_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_workflow(
    workflow_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> Response:
    """Delete a workflow definition (admin only)."""
    deleted = workflow_repo.delete(workflow_id, str(org_id))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")
    return Response(status_code=204)


@workflow_router.post("/{workflow_id}/execute", dependencies=[Depends(require_operator)])
async def execute_test_workflow(
    workflow_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    req: DryRunExecuteRequest | None = None,
) -> dict[str, Any]:
    """Execute in-memory dry-run test trace without mutating live state (D17)."""
    wf = workflow_repo.get(workflow_id, str(org_id))
    if not wf:
        raise HTTPException(status_code=404, detail=f"Workflow '{workflow_id}' not found.")

    sample_alert = (req and req.sample_alert) or SiemAlert(
        id="sample-dry-run-001",
        rule_id=5710,
        level=7,
        description="SSH authentication failure sample for dry-run",
        location="/var/log/auth.log",
        mitre="T1110",
        agent_name="sample-web-01",
    )

    sample_report = InvestigationReport(
        alert_id=sample_alert.id,
        policy=PolicyResult(
            alert_id=sample_alert.id,
            tier=Tier.TRIAGE,
            should_investigate=True,
            reason="Sample policy triage",
        ),
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Dry-run investigation verdict",
            recommended_actions=["Review logs"],
        ),
        evidence=Evidence(
            alert=sample_alert,
            agent_name="sample-web-01",
            threat_intel="Simulated threat intel report",
            context_notes="Dry run execution context",
        ),
    )

    ctx = await pipeline_runner.workflow_engine.execute_workflow(
        workflow=wf,
        alert=sample_alert,
        base_report=sample_report,
        org_id=str(org_id),
        deployment=pipeline_runner.deployment,
        dry_run=True,
    )

    return {
        "status": "validated" if ctx.status == "COMPLETED" else ctx.status,
        "outcome": ctx.outcome,
        "workflow_id": workflow_id,
        "dry_run": True,
        "nodes_validated": len(wf.nodes),
        "executed_nodes": ctx.executed_nodes,
        "node_statuses": ctx.node_statuses,
        "node_outputs": ctx.node_outputs,
        "errors": ctx.errors,
        "side_effects_executed": ctx.side_effects_executed,
    }


# ─── Agents Router ───────────────────────────────────────────────────────────────


@agent_router.get("")
async def list_agents(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> list[SocAgent]:
    """List all AI SOC agents in the active fleet."""
    return agent_repo.list_for_org(str(org_id))


@agent_router.get("/actions")
async def list_agent_actions(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    action_repo: Annotated[SqliteActionLogRepository, Depends(get_action_log_repo)],
    limit: int = 100,
    actor_type: str | None = None,
    action_type: str | None = None,
) -> list[dict[str, Any]]:
    """List recorded real-time agent, playbook, and guardrail actions."""
    return action_repo.list_actions(
        org_id=str(org_id),
        limit=limit,
        actor_type=actor_type,
        action_type=action_type,
    )


@agent_router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> SocAgent:
    """Fetch single AI SOC agent by ID."""
    agent = agent_repo.get(agent_id, str(org_id))
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return agent


@agent_router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def create_agent(
    req: CreateAgentRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> SocAgent:
    """Deploy a new AI SOC agent with custom master system prompt."""
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
    return agent_repo.save(new_agent, str(org_id))


@agent_router.patch("/{agent_id}", dependencies=[Depends(require_admin)])
async def update_agent(
    agent_id: str,
    req: UpdateAgentRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> SocAgent:
    """Update agent status (ON/OFF toggle) or master system prompt."""
    agent = agent_repo.get(agent_id, str(org_id))
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

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
    return agent_repo.save(updated_agent, str(org_id))


@agent_router.delete("/{agent_id}", dependencies=[Depends(require_admin)])
async def delete_agent(
    agent_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> dict[str, Any]:
    """Delete an AI SOC agent (admin only)."""
    deleted = agent_repo.delete(agent_id, str(org_id))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")
    return {"status": "deleted", "agent_id": agent_id}


# ─── Containment Allowlist Router ─────────────────────────────────────────────────


@allowlist_router.get("")
async def list_allowlist_entries(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    allowlist_repo: Annotated[SqliteAllowlistRepository, Depends(get_allowlist_repo)],
) -> list[dict[str, Any]]:
    """List all protected hosts/IPs in the containment safety allowlist (D12)."""
    return allowlist_repo.list_entries(str(org_id))


@allowlist_router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def add_allowlist_entry(
    req: CreateAllowlistRequest,
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    allowlist_repo: Annotated[SqliteAllowlistRepository, Depends(get_allowlist_repo)],
) -> dict[str, Any]:
    """Add a new host or IP to the containment safety allowlist."""
    entry_id = f"al-{secrets.token_hex(4)}"
    return allowlist_repo.add_entry(
        entry_id=entry_id,
        org_id=str(org_id),
        kind=req.kind,
        value=req.value,
        note=req.note,
        created_by=user.display_name or user.email,
    )


@allowlist_router.delete("/{entry_id}", dependencies=[Depends(require_admin)])
async def delete_allowlist_entry(
    entry_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    allowlist_repo: Annotated[SqliteAllowlistRepository, Depends(get_allowlist_repo)],
) -> dict[str, Any]:
    """Remove an entry from the containment safety allowlist."""
    deleted = allowlist_repo.delete_entry(str(org_id), entry_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Allowlist entry '{entry_id}' not found.")
    return {"status": "deleted", "entry_id": entry_id}


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


# ─── Decoy & Red Team Honeytoken Router ──────────────────────────────────────────

decoy_router = APIRouter(prefix="/decoy", tags=["Deception & Red Team Canary"])


@decoy_router.get("/vault-secrets")
async def get_decoy_vault_secrets(
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Simulated vulnerable endpoint exposing fake cloud & database credentials."""
    from uuid import uuid4

    from terminus.core.ids import AgentId, RuleId

    org_id_header = request.headers.get("X-Org-ID")
    target_org_id = OrgId(org_id_header) if org_id_header else OrgId("org-default")
    if not org_id_header:
        all_orgs = org_service.org_store.list_all()
        if all_orgs:
            target_org_id = all_orgs[0].org_id

    client_ip = request.client.host if request.client else "unknown-client"
    alert = SiemAlert(
        id=f"canary-vault-{uuid4().hex[:8]}",
        rule_id=RuleId(100099),
        level=15,
        description="Canary Token Accessed: Decoy Cloud Vault Credentials Retrieved (T1552)",
        mitre="T1552",
        agent_id=AgentId("srv-vault-01"),
        agent_name="internal-vault-db01",
        full_log=f"HONEYTOKEN TRIPWIRE: Client {client_ip} fetched fake AWS key AKIA_CANARY_HONEYTOKEN_9941_REDTEAM and postgres connection URI from /decoy/vault-secrets",
        timestamp=request.headers.get("X-Simulated-Time", datetime.now(UTC).isoformat()),
        src_ip=client_ip,
    )
    await pipeline_runner.process_alert(alert, target_org_id)

    return {
        "status": "warning",
        "service": "decoy-vault-internal",
        "disclaimer": "SYNTHETIC DECOY DATA FOR RED TEAM INTERCEPTION DEMONSTRATION",
        "secrets": {
            "aws_access_key_id": "AKIA_CANARY_HONEYTOKEN_9941_REDTEAM",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY_CANARY",
            "db_connection_uri": "postgres://prod_admin:FakeSecretPassword2026!@internal-db:5432/customer_pii",
            "stripe_api_key": "sk_live_canary_honeytoken_synthetic_secret",
        },
    }


@decoy_router.get("/customer-pii")
async def get_decoy_customer_pii(
    request: Request,
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
) -> dict[str, Any]:
    """Simulated sensitive database endpoint exposing synthetic customer PII."""
    from uuid import uuid4

    from terminus.core.ids import AgentId, RuleId

    org_id_header = request.headers.get("X-Org-ID")
    target_org_id = OrgId(org_id_header) if org_id_header else OrgId("org-default")
    if not org_id_header:
        all_orgs = org_service.org_store.list_all()
        if all_orgs:
            target_org_id = all_orgs[0].org_id

    client_ip = request.client.host if request.client else "unknown-client"
    alert = SiemAlert(
        id=f"canary-pii-{uuid4().hex[:8]}",
        rule_id=RuleId(100100),
        level=15,
        description="Canary Table Read: Synthetic Customer PII Decoy Exfiltrated (T1567)",
        mitre="T1567",
        agent_id=AgentId("srv-vault-01"),
        agent_name="internal-vault-db01",
        full_log=f"HONEYTOKEN TRIPWIRE: Client {client_ip} dumped synthetic customer PII table containing 2 decoy customer SSNs and credit card hashes from /decoy/customer-pii",
        timestamp=request.headers.get("X-Simulated-Time", datetime.now(UTC).isoformat()),
        src_ip=client_ip,
    )
    await pipeline_runner.process_alert(alert, target_org_id)

    return {
        "status": "warning",
        "record_count": 2,
        "disclaimer": "SYNTHETIC DECOY PII FOR RED TEAM INTERCEPTION DEMONSTRATION",
        "records": [
            {
                "id": "usr-fake-01",
                "name": "Jane Doe",
                "ssn": "987-65-4321",
                "email": "jdoe@synthetic.corp",
                "card_token": "tok_visa_4242",
            },
            {
                "id": "usr-fake-02",
                "name": "John Smith",
                "ssn": "987-12-3456",
                "email": "jsmith@synthetic.corp",
                "card_token": "tok_mc_5555",
            },
        ],
    }
