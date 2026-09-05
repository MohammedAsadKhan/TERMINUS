"""Additional authenticated APIs used by the React console."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from terminus.auth.models import PublicUser, User
from terminus.auth.service import UserStore
from terminus.config import Settings, get_settings
from terminus.core.ids import OrgId, TicketId, UserId
from terminus.licensing.crypto import LicenseError
from terminus.licensing.service import LicenseService
from terminus.models import SocAgent, Workflow
from terminus.orgs.models import Membership, OrganizationRole
from terminus.orgs.service import LastAdminError, OrganizationService
from terminus.orgs.store import MembershipStore, OrganizationStore
from terminus.pipeline.runner import PipelineRunner
from terminus.server.deps import (
    get_current_org,
    get_current_user,
    get_license_service,
    get_membership_store,
    get_org_service,
    get_org_store,
    get_pipeline_runner,
    get_tenant_agents,
    get_tenant_workflows,
    get_user_store,
    require_admin,
)

router = APIRouter(tags=["Console"])
CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentOrg = Annotated[OrgId, Depends(get_current_org)]


@router.get("/auth/me")
async def me(user: CurrentUser) -> PublicUser:
    return PublicUser.model_validate(user)


@router.get("/incidents/{ticket_id}")
async def incident(ticket_id: TicketId, org_id: CurrentOrg, runner: Annotated[PipelineRunner, Depends(get_pipeline_runner)]) -> dict[str, Any]:
    return await runner.deployment.ticket_store.get_ticket(ticket_id, org_id)


@router.get("/orgs/current")
async def organization(
    org_id: CurrentOrg, user: CurrentUser,
    orgs: Annotated[OrganizationStore, Depends(get_org_store)],
    members: Annotated[MembershipStore, Depends(get_membership_store)],
    users: Annotated[UserStore, Depends(get_user_store)],
    licenses: Annotated[LicenseService, Depends(get_license_service)],
) -> dict[str, Any]:
    org = orgs.get(org_id, org_id)
    license_data = None
    error = None
    try:
        if org.license_ref:
            license_data = licenses.validate(org.license_ref)
    except LicenseError as err:
        error = str(err)
    people = []
    for member in members.memberships_for(org_id):
        person = users.get(member.user_id)
        people.append({**member.model_dump(), "user": PublicUser.model_validate(person) if person else None})
    return {"organization": org, "role": members.role_of(org_id, user.user_id), "members": people, "license": license_data, "license_error": error}


class RoleRequest(BaseModel):
    role: OrganizationRole


@router.patch("/orgs/{target_org}/members/{user_id}", dependencies=[Depends(require_admin)])
async def change_role(target_org: OrgId, user_id: UserId, req: RoleRequest, org_id: CurrentOrg, user: CurrentUser, service: Annotated[OrganizationService, Depends(get_org_service)]) -> Membership:
    if target_org != org_id:
        raise HTTPException(403, "Cannot manage another organization")
    try:
        return service.change_role(org_id, actor_id=user.user_id, user_id=user_id, new_role=req.role)
    except LastAdminError as err:
        raise HTTPException(409, str(err)) from err


@router.delete("/orgs/{target_org}/members/{user_id}", status_code=204, dependencies=[Depends(require_admin)])
async def remove_member(target_org: OrgId, user_id: UserId, org_id: CurrentOrg, user: CurrentUser, service: Annotated[OrganizationService, Depends(get_org_service)]) -> None:
    if target_org != org_id:
        raise HTTPException(403, "Cannot manage another organization")
    try:
        service.remove_member(org_id, actor_id=user.user_id, user_id=user_id)
    except LastAdminError as err:
        raise HTTPException(409, str(err)) from err


@router.delete("/agents/{agent_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_agent(agent_id: str, agents: Annotated[dict[str, SocAgent], Depends(get_tenant_agents)], workflows: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)]) -> None:
    if any(w.agent_id == agent_id or any(n.config.get("agent_id") == agent_id for n in w.nodes) for w in workflows.values()):
        raise HTTPException(409, "Remove this agent from workflows before deleting it")
    if agents.pop(agent_id, None) is None:
        raise HTTPException(404, "Agent not found")


@router.delete("/workflows/{workflow_id}", status_code=204, dependencies=[Depends(require_admin)])
async def delete_workflow(workflow_id: str, workflows: Annotated[dict[str, Workflow], Depends(get_tenant_workflows)]) -> None:
    if workflows.pop(workflow_id, None) is None:
        raise HTTPException(404, "Workflow not found")


def workflow_errors(workflow: Workflow) -> list[str]:
    errors: list[str] = []
    ids = [n.id for n in workflow.nodes]
    if not workflow.name.strip():
        errors.append("A workflow name is required")
    if len(ids) != len(set(ids)):
        errors.append("Node IDs must be unique")
    if len(workflow.nodes) > 200 or len(workflow.edges) > 400:
        errors.append("Workflow exceeds the 200 node / 400 edge limit")
        return errors
    if len({e.id for e in workflow.edges}) != len(workflow.edges):
        errors.append("Edge IDs must be unique")
    if any(e.source not in ids or e.target not in ids for e in workflow.edges):
        errors.append("Every edge must connect existing nodes")
    remaining = set(ids)
    while remaining:
        roots = {n for n in remaining if not any(e.target == n and e.source in remaining for e in workflow.edges)}
        if not roots:
            errors.append("Cycles are not supported; use an explicit bounded loop node")
            break
        remaining -= roots
    return errors


@router.get("/system")
async def system_status(user: CurrentUser, settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    return {
        "version": "0.2.0", "storage": "memory", "transport": "polling",
        "llm_mode": "remote" if settings.llm_api_key else "scripted",
        "llm_model": settings.llm_model if settings.llm_api_key else "Scripted development responses",
        "live_response": False, "workflow_execution": False,
        "integrations": [
            {"id": "wazuh", "name": "Wazuh", "category": "SIEM", "configured": bool(settings.wazuh_url), "description": "Alert ingestion and host context", "setting": "TERMINUS_WAZUH_URL"},
            {"id": "slack", "name": "Slack", "category": "Notifications", "configured": bool(settings.slack_webhook), "description": "Investigation notifications", "setting": "TERMINUS_SLACK_WEBHOOK"},
            {"id": "twilio", "name": "Twilio", "category": "Notifications", "configured": bool(settings.twilio_sid and settings.twilio_token), "description": "SMS investigation notifications", "setting": "TERMINUS_TWILIO_SID"},
            {"id": "jira", "name": "Jira", "category": "Ticketing", "configured": bool(settings.jira_url and settings.jira_token), "description": "External issue creation adapter", "setting": "TERMINUS_JIRA_URL"},
        ],
    }
