"""First Heritage Community Bank — Interactive Retail Banking Honeypot & Decoy Gateway.

Provides a realistic local community bank website for red team demonstrations, complete with:
- Public banking homepage & customer login portal
- Authenticated customer dashboard (checking, savings, transactions, transfers)
- Simulated normal user traffic endpoints (benign telemetry filtered into IGNORE policy tier)
- Vulnerable search & transfer endpoints triggering exploit alerts (ESCALATE policy tier)
- Decoy core banking treasury keys & customer financial database exfiltration honeytokens
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from terminus.core.ids import AgentId, OrgId, RuleId
from terminus.models import SiemAlert
from terminus.orgs.service import OrganizationService
from terminus.pipeline.runner import PipelineRunner
from terminus.server.deps import get_org_service, get_pipeline_runner

bank_router = APIRouter(prefix="/bank", tags=["Banking Honeypot & Retail Decoy"])


def _get_target_org_id(request: Request, org_service: OrganizationService) -> OrgId:
    """Retrieve target org ID from header or fallback to default bootstrapped org."""
    header_org = request.headers.get("X-Org-ID")
    if header_org:
        return OrgId(header_org)
    all_orgs = org_service.org_store.list_all()
    if all_orgs:
        return all_orgs[0].org_id
    return OrgId("org-default")


def _get_request_timestamp(request: Request) -> str:
    """Retrieve simulated event timestamp from header or default to current UTC time."""
    sim_time = request.headers.get("X-Simulated-Time")
    if sim_time:
        return sim_time
    return datetime.now(UTC).isoformat()


class BankLoginRequest(BaseModel):
    username: str
    password: str


class TransferRequest(BaseModel):
    to_account: str
    amount: float
    memo: str = "Online Payment"


@bank_router.get("", response_class=HTMLResponse)
@bank_router.get("/", response_class=HTMLResponse)
async def bank_home() -> HTMLResponse:
    """Public homepage of First Heritage Community Bank."""
    return HTMLResponse("<html><body><h1>First Heritage Community Bank</h1><p>Online Banking Honeypot active.</p></body></html>")


@bank_router.post("/api/login")
async def bank_login(
    req: BankLoginRequest,
    request: Request,
    org_service: Annotated[OrganizationService, Depends(get_org_service)],
    pipeline_runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)],
) -> JSONResponse:
    """Customer authentication endpoint."""
    target_org_id = _get_target_org_id(request, org_service)
    client_ip = request.client.host if request.client else "192.168.1.100"

    is_valid = (
        (req.username.lower() == "sarah.jenkins" and req.password == "BankPass2026!")
        or (req.username.lower() == "customer" and req.password == "password")
    )

    if is_valid:
        alert = SiemAlert(
            id=f"bank-auth-ok-{uuid4().hex[:8]}",
            rule_id=RuleId(100010),
            level=3,
            description="Online Banking: Customer Authentication Successful",
            mitre=None,
            agent_id=AgentId("srv-bank-web01"),
            agent_name="bank-web-frontend-01",
            full_log=f"INFO: Valid session initialized for user '{req.username}' from {client_ip}.",
            timestamp=_get_request_timestamp(request),
        )
        await pipeline_runner.process_alert(alert, target_org_id)
        return JSONResponse(
            content={"status": "success", "message": f"Welcome back, {req.username}!"}
        )

    # Failed login anomaly -> Level 7 -> TRIAGE policy tier
    alert = SiemAlert(
        id=f"bank-auth-fail-{uuid4().hex[:8]}",
        rule_id=RuleId(100015),
        level=7,
        description="Online Banking: Consecutive Failed Authentication Attempts (Brute Force Anomaly)",
        mitre="T1110",
        agent_id=AgentId("srv-bank-web01"),
        agent_name="bank-web-frontend-01",
        full_log=f"WARNING: Authentication failure for user '{req.username}' from {client_ip}. Invalid password hash.",
        timestamp=_get_request_timestamp(request),
    )
    await pipeline_runner.process_alert(alert, target_org_id)
    return JSONResponse(
        status_code=401,
        content={"status": "error", "detail": "Invalid username or password."},
    )
