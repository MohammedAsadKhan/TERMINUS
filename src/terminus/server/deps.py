"""FastAPI dependency injection module for services, authentication, and multi-tenant authorization."""

from __future__ import annotations

import os
import secrets
from typing import Annotated

from fastapi import Cookie, Depends, Header, HTTPException, status

from terminus.agent.investigator import InvestigationAgent
from terminus.agent.tools import InvestigationTools
from terminus.auth.models import User
from terminus.auth.service import AuthService, UserStore
from terminus.auth.storage import SqliteSessionStore, SqliteUserStore
from terminus.config import Settings, get_settings
from terminus.core.ids import OrgId, SessionToken
from terminus.correlation.stitcher import CampaignStitcher
from terminus.licensing.service import LicenseService
from terminus.llm.base import LlmClient
from terminus.llm.client import OpenAiCompatibleLlm, ScriptedLlm
from terminus.models import (
    AgentStatus,
    DailyIncidentReport,
    SocAgent,
    Workflow,
)
from terminus.notifiers.builder import CompositeNotifier
from terminus.notifiers.log import LogNotifier
from terminus.notifiers.slack import SlackNotifier
from terminus.notifiers.twilio import TwilioSmsNotifier
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.service import OrganizationService
from terminus.orgs.storage import SqliteMembershipStore, SqliteOrganizationStore
from terminus.orgs.store import MembershipStore, OrganizationStore
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.runner import PipelineRunner
from terminus.pipeline.specialist_bridge import (
    DATABASE_ENV,
    ROLES_ENV,
    SpecialistBridge,
    specialist_bridge_from_environ,
)
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.policies.engine import PolicyEngine
from terminus.siem.unavailable import UnavailableSiemClient
from terminus.siem.wazuh import WazuhClient
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteActionLogRepository,
    SqliteAgentRepository,
    SqliteAlertClaimRepository,
    SqliteAllowlistRepository,
    SqliteApprovalRepository,
    SqliteIncidentRepository,
    SqliteMembershipRepository,
    SqliteOrgRepository,
    SqliteUserRepository,
    SqliteWorkflowRepository,
    SqliteWorkflowRunRepository,
)
from terminus.ticketing.jira import JiraTickets

# ─── Global Database & Repositories ──────────────────────────────────────────────────

_sqlite_incident_repo = SqliteIncidentRepository()
_sqlite_org_repo = SqliteOrgRepository()
_sqlite_membership_repo = SqliteMembershipRepository()
_sqlite_user_repo = SqliteUserRepository()
_sqlite_workflow_repo = SqliteWorkflowRepository()
_sqlite_agent_repo = SqliteAgentRepository()
_sqlite_workflow_run_repo = SqliteWorkflowRunRepository()
_sqlite_approval_repo = SqliteApprovalRepository()
_sqlite_alert_claim_repo = SqliteAlertClaimRepository()
_sqlite_allowlist_repo = SqliteAllowlistRepository()
_sqlite_action_log_repo = SqliteActionLogRepository()

# Persistent identity stores; campaign aggregation/report history remain in memory.
_identity_db = Database.get_instance()
_user_store = SqliteUserStore(_identity_db)
_org_store = SqliteOrganizationStore(_identity_db)
_membership_store = SqliteMembershipStore(_identity_db)
_ticket_store = _sqlite_incident_repo
_campaign_stitcher = CampaignStitcher()
_auth_service = AuthService(_user_store, session_store=SqliteSessionStore(_identity_db))
_reports_store: dict[str, dict[str, DailyIncidentReport]] = {}


def bootstrap_default_admin() -> None:
    """Initialize a new local demo or explicitly configured hosted owner once."""
    from datetime import UTC, datetime

    from terminus.licensing.models import LicenseTier

    settings = get_settings()
    configured = bool(settings.bootstrap_admin_email)
    if settings.deployment_mode == "hosted" and not configured:
        return
    admin_email = settings.bootstrap_admin_email or "admin@terminus.local"
    admin_pass = settings.bootstrap_admin_password or "Password123!"
    license_svc = LicenseService(secret=settings.license_secret)
    with _identity_db.transaction():
        # Never reset an existing password or restore a removed membership.
        if _user_store.get_by_email(admin_email):
            return
        user = _auth_service.register(admin_email, admin_pass, "Terminus Administrator")
        org_id = OrgId("org-bootstrap-" + secrets.token_hex(8)) if configured else OrgId("org-terminus-demo")
        existing = _identity_db.fetchone("SELECT license_ref FROM organizations WHERE org_id=?", (org_id,))
        if existing and _membership_store.memberships_for(org_id):
            raise ValueError("Demo organization already has an owner; configure a bootstrap account")
        license_ref = license_svc.generate(org_id=org_id, tier=LicenseTier.TRIAL, days=30)
        org = Organization(org_id=org_id, name="Terminus Security Operations", created_at=datetime.now(UTC), license_ref=license_ref)
        if existing:
            _org_store.update(org, org_id)
        else:
            _org_store.create(org, org_id)
        _membership_store.create(Membership(org_id=org_id, user_id=user.user_id, role=OrganizationRole.ADMIN))

bootstrap_default_admin()

_default_seed_agents = [
    SocAgent(
        id="agent-triage",
        name="Triage Sentinel",
        role_description="Sub-millisecond alert filtering, MITRE tag correlation, and noise suppression.",
        master_prompt="You are the Triage Sentinel AI Agent. Your primary role is to inspect incoming raw SIEM telemetry from Wazuh, evaluate alert severity levels against organizational policy rules, and filter out low-level operational noise without consuming unnecessary LLM token quota.",
        status=AgentStatus.ACTIVE,
        incidents_processed=0,
        avg_sla_ms=0.0,
        created_at="2026-09-01T00:00:00Z",
    ),
    SocAgent(
        id="agent-forensic",
        name="Forensic Investigator",
        role_description="Deep LLM evidence collection, threat intel enrichment, payload breakdown, and root cause reasoning.",
        master_prompt="You are the Forensic Investigator AI Agent. Your role is to perform deep-dive analysis on high-severity security incidents. You gather process execution trees, inspect network payload strings, correlate IOCs against threat intelligence feeds, and render structured JSON verdicts with high-confidence root cause explanations.",
        status=AgentStatus.ACTIVE,
        incidents_processed=0,
        avg_sla_ms=0.0,
        created_at="2026-09-01T00:00:00Z",
    ),
    SocAgent(
        id="agent-containment",
        name="Containment Operator",
        role_description="Executes network boundary firewall blocks, host workstation isolations, and service credential revocations.",
        master_prompt="You are the Containment Operator AI Agent. Your role is to execute automated remediation playbooks when critical threats are identified.",
        status=AgentStatus.ACTIVE,
        incidents_processed=0,
        avg_sla_ms=0.0,
        created_at="2026-09-01T00:00:00Z",
    ),
    SocAgent(
        id="agent-threat-hunter",
        name="Proactive Threat Hunter",
        role_description="Iteratively polls endpoints every 5 minutes for anomalous memory execution and persistence mechanisms.",
        master_prompt="You are the Proactive Threat Hunter AI Agent. You operate on a recurring scheduled loop, polling active workloads.",
        status=AgentStatus.ACTIVE,
        incidents_processed=0,
        avg_sla_ms=0.0,
        created_at="2026-09-01T00:00:00Z",
    ),
]

for seed_agent in _default_seed_agents:
    _sqlite_agent_repo.save(seed_agent, "org-default")
    _sqlite_agent_repo.save(seed_agent, "org-terminus-demo")


def get_sqlite_workflow_repo() -> SqliteWorkflowRepository:
    return _sqlite_workflow_repo


def get_workflow_repo() -> SqliteWorkflowRepository:
    return _sqlite_workflow_repo


def get_sqlite_agent_repo() -> SqliteAgentRepository:
    return _sqlite_agent_repo


def get_agent_repo() -> SqliteAgentRepository:
    return _sqlite_agent_repo


def get_workflow_run_repo() -> SqliteWorkflowRunRepository:
    return _sqlite_workflow_run_repo


def get_approval_repo() -> SqliteApprovalRepository:
    return _sqlite_approval_repo


def get_alert_claim_repo() -> SqliteAlertClaimRepository:
    return _sqlite_alert_claim_repo


def get_allowlist_repo() -> SqliteAllowlistRepository:
    return _sqlite_allowlist_repo


def get_incident_repo() -> SqliteIncidentRepository:
    return _sqlite_incident_repo


def get_action_log_repo() -> SqliteActionLogRepository:
    return _sqlite_action_log_repo


def get_agents_store(
    org_id: Annotated[OrgId, Depends(lambda: OrgId("org-default"))],
) -> dict[str, SocAgent]:
    agents = _sqlite_agent_repo.list_for_org(str(org_id))
    return {a.id: a for a in agents}


def get_workflows_store(
    org_id: Annotated[OrgId, Depends(lambda: OrgId("org-default"))],
) -> dict[str, Workflow]:
    wfs = _sqlite_workflow_repo.list_for_org(str(org_id))
    return {w.id: w for w in wfs}


def get_user_store() -> UserStore:
    return SqliteUserStore()


def get_org_store() -> SqliteOrganizationStore:
    return SqliteOrganizationStore()


def get_membership_store() -> SqliteMembershipStore:
    return SqliteMembershipStore()


def get_auth_service() -> AuthService:
    return AuthService(SqliteUserStore(), session_store=SqliteSessionStore())


def get_license_service(
    settings: Annotated[Settings, Depends(get_settings)],
) -> LicenseService:
    return LicenseService(secret=settings.license_secret)


def get_org_service(
    org_store: Annotated[OrganizationStore, Depends(get_org_store)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
    license_service: Annotated[LicenseService, Depends(get_license_service)],
) -> OrganizationService:
    return OrganizationService(
        org_store=org_store,
        membership_store=membership_store,
        license_service=license_service,
    )


def get_llm_client(
    settings: Annotated[Settings, Depends(get_settings)],
) -> LlmClient:
    if settings.llm_api_key:
        return OpenAiCompatibleLlm(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
        )
    return ScriptedLlm()


def get_pipeline_runner(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PipelineRunner:
    llm = get_llm_client(settings)

    if settings.wazuh_url:
        siem = WazuhClient(
            base_url=settings.wazuh_url,
            username=settings.wazuh_user,
            password=settings.wazuh_password,
        )
    else:
        siem = UnavailableSiemClient()

    notifiers = [LogNotifier()]
    if settings.slack_webhook:
        notifiers.append(SlackNotifier(webhook_url=settings.slack_webhook))
    if settings.twilio_sid and settings.twilio_token:
        notifiers.append(
            TwilioSmsNotifier(
                account_sid=settings.twilio_sid,
                auth_token=settings.twilio_token,
                from_number=settings.twilio_from,
                to_number=settings.sms_to,
            )
        )

    composite_notifier = CompositeNotifier(notifiers)

    if settings.jira_url and settings.jira_token:
        external_ticket_store = JiraTickets(
            jira_url=settings.jira_url,
            username=settings.jira_user,
            api_token=settings.jira_token,
            project_key=settings.jira_project,
        )
    else:
        external_ticket_store = None

    policy_engine = PolicyEngine()
    tools = InvestigationTools(siem)
    agent = InvestigationAgent(llm=llm, tools=tools, policy_engine=policy_engine)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=composite_notifier,
        ticket_store=_sqlite_incident_repo,
        external_ticket_store=external_ticket_store,
    )
    workflow_engine = WorkflowEngine(specialist_bridge=_specialist_bridge())
    return PipelineRunner(deployment, workflow_engine=workflow_engine, stitcher=_campaign_stitcher)


_BRIDGE_CACHE: dict[tuple[int, str], SpecialistBridge | None] = {}


def _specialist_bridge() -> SpecialistBridge | None:
    """Bridge only when TERMINUS_SPECIALIST_ROLES declares deployed handlers (else legacy).

    Cached per database and declaration. Never starts a scheduler; handlers run in
    the separate scheduler process.
    """
    db = Database.get_instance()
    key = (id(db), os.environ.get(ROLES_ENV, "") + "|" + os.environ.get(DATABASE_ENV, ""))
    if key not in _BRIDGE_CACHE:
        _BRIDGE_CACHE.clear()
        _BRIDGE_CACHE[key] = specialist_bridge_from_environ(db)
    return _BRIDGE_CACHE[key]


# ─── Auth & Multi-Tenancy Dependencies ─────────────────────────────────────────────


def get_current_user(
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    authorization: Annotated[str | None, Header()] = None,
    x_session_token: Annotated[str | None, Header(alias="X-Session-Token")] = None,
    terminus_session: Annotated[str | None, Cookie()] = None,
) -> User:
    token_str = x_session_token
    if not token_str and authorization:
        if authorization.startswith("Bearer "):
            token_str = authorization[7:]
        else:
            token_str = authorization

    if not token_str:
        token_str = terminus_session

    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token header",
        )

    try:
        user = auth_service.verify(SessionToken(token_str))
        if get_settings().deployment_mode == "hosted" and user.email == "admin@terminus.local":
            raise ValueError("Local demo account is disabled in hosted mode")
        return user
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired session token: {err}",
        ) from err


def get_current_org(
    user: Annotated[User, Depends(get_current_user)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
    x_org_id: Annotated[str | None, Header(alias="X-Org-ID")] = None,
) -> OrgId:
    if not x_org_id:
        user_orgs = membership_store.orgs_for_user(user.user_id)
        if user_orgs:
            return user_orgs[0].org_id
        raise HTTPException(status_code=403, detail="User has no organization membership")

    org_id = OrgId(x_org_id)
    role = membership_store.role_of(org_id, user.user_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User is not a member of organization '{org_id}'",
        )
    return org_id


def get_webhook_org(
    org_id: Annotated[OrgId, Depends(get_current_org)],
) -> OrgId:
    return org_id


def get_current_user_role(
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
) -> str:
    role = membership_store.role_of(org_id, user.user_id)
    if role == OrganizationRole.ADMIN:
        return "admin"
    if role == OrganizationRole.MEMBER:
        return "analyst"
    return "viewer"


def require_admin(
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
) -> None:
    role = membership_store.role_of(org_id, user.user_id)
    if role != OrganizationRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires organization admin role",
        )


def get_reports_store() -> dict[str, dict[str, DailyIncidentReport]]:
    return _reports_store


def require_operator(
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    members: Annotated[MembershipStore, Depends(get_membership_store)],
) -> None:
    if members.role_of(org_id, user.user_id) not in (
        OrganizationRole.ADMIN, OrganizationRole.MEMBER
    ):
        raise HTTPException(status_code=403, detail="Operation requires a member or admin role")


def get_tenant_agents(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    agent_repo: Annotated[SqliteAgentRepository, Depends(get_agent_repo)],
) -> dict[str, SocAgent]:
    agents = agent_repo.list_for_org(str(org_id))
    return {a.id: a for a in agents}


def get_tenant_workflows(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    workflow_repo: Annotated[SqliteWorkflowRepository, Depends(get_workflow_repo)],
) -> dict[str, Workflow]:
    wfs = workflow_repo.list_for_org(str(org_id))
    return {w.id: w for w in wfs}
