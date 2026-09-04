"""FastAPI dependency injection module for services, authentication, and multi-tenant authorization."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from terminus.agent.investigator import InvestigationAgent
from terminus.agent.tools import InvestigationTools
from terminus.auth.models import User
from terminus.auth.service import AuthService, UserStore
from terminus.config import Settings, get_settings
from terminus.core.ids import OrgId, SessionToken
from terminus.licensing.service import LicenseService
from terminus.llm.client import OpenAiCompatibleLlm, ScriptedLlm
from terminus.notifiers.builder import CompositeNotifier
from terminus.notifiers.log import LogNotifier
from terminus.notifiers.slack import SlackNotifier
from terminus.notifiers.twilio import TwilioSmsNotifier
from terminus.orgs.models import OrganizationRole
from terminus.orgs.service import OrganizationService
from terminus.orgs.store import MembershipStore, OrganizationStore
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.runner import PipelineRunner
from terminus.policies.engine import PolicyEngine
from terminus.siem.static import StaticSiemClient
from terminus.siem.wazuh import WazuhClient
from terminus.ticketing.jira import JiraTickets
from terminus.ticketing.memory import MemoryTickets

# ─── Global State Container (In-Memory for MVP-1) ──────────────────────────────────

_user_store = UserStore()
_org_store = OrganizationStore()
_membership_store = MembershipStore()
_ticket_store = MemoryTickets()
_auth_service = AuthService(_user_store)


def get_user_store() -> UserStore:
    """Return user store singleton."""
    return _user_store


def get_org_store() -> OrganizationStore:
    """Return org store singleton."""
    return _org_store


def get_membership_store() -> MembershipStore:
    """Return membership store singleton."""
    return _membership_store


def get_auth_service() -> AuthService:
    """Return auth service singleton."""
    return _auth_service


def get_license_service(
    settings: Annotated[Settings, Depends(get_settings)],
) -> LicenseService:
    """Return license service instance."""
    return LicenseService(secret=settings.license_secret)


def get_org_service(
    org_store: Annotated[OrganizationStore, Depends(get_org_store)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
    license_service: Annotated[LicenseService, Depends(get_license_service)],
) -> OrganizationService:
    """Return organization service instance."""
    return OrganizationService(
        org_store=org_store,
        membership_store=membership_store,
        license_service=license_service,
    )


def get_pipeline_runner(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PipelineRunner:
    """Construct and return pipeline runner based on active settings."""
    if settings.llm_api_key:
        llm = OpenAiCompatibleLlm(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
        )
    else:
        llm = ScriptedLlm()

    if settings.wazuh_url:
        siem = WazuhClient(
            base_url=settings.wazuh_url,
            username=settings.wazuh_user,
            password=settings.wazuh_password,
        )
    else:
        siem = StaticSiemClient()

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
        ticket_store = JiraTickets(
            jira_url=settings.jira_url,
            username=settings.jira_user,
            api_token=settings.jira_token,
            project_key=settings.jira_project,
        )
    else:
        ticket_store = _ticket_store

    policy_engine = PolicyEngine()
    tools = InvestigationTools(siem)
    agent = InvestigationAgent(llm=llm, tools=tools, policy_engine=policy_engine)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=composite_notifier,
        ticket_store=ticket_store,
    )
    return PipelineRunner(deployment)


# ─── Auth & Multi-Tenancy Dependencies ─────────────────────────────────────────────


def get_current_user(
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    authorization: Annotated[str | None, Header()] = None,
    x_session_token: Annotated[str | None, Header(alias="X-Session-Token")] = None,
) -> User:
    """Verify session token and return authenticated user."""
    token_str = x_session_token
    if not token_str and authorization:
        if authorization.startswith("Bearer "):
            token_str = authorization[7:]
        else:
            token_str = authorization

    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token header",
        )

    try:
        return auth_service.verify(SessionToken(token_str))
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
    """Verify tenant header and user membership for current request."""
    if not x_org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing tenant header 'X-Org-ID'",
        )

    org_id = OrgId(x_org_id)
    role = membership_store.role_of(org_id, user.user_id)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User is not a member of organization '{org_id}'",
        )
    return org_id


def get_webhook_org(
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
    authorization: Annotated[str | None, Header()] = None,
    x_session_token: Annotated[str | None, Header(alias="X-Session-Token")] = None,
    x_org_id: Annotated[str | None, Header(alias="X-Org-ID")] = None,
) -> OrgId:
    """Resolve target tenant for webhooks and incident feed with optional session validation."""
    target_org = OrgId(x_org_id) if x_org_id else OrgId("org-00000001")
    token_str = x_session_token
    if not token_str and authorization:
        if authorization.startswith("Bearer "):
            token_str = authorization[7:]
        else:
            token_str = authorization

    if token_str:
        try:
            user = auth_service.verify(SessionToken(token_str))
            role = membership_store.role_of(target_org, user.user_id)
            if role is None:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User is not a member of organization '{target_org}'",
                )
        except ValueError:
            pass
    return target_org


def require_admin(
    user: Annotated[User, Depends(get_current_user)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    membership_store: Annotated[MembershipStore, Depends(get_membership_store)],
) -> None:
    """Enforce that current user has admin role in current org."""
    role = membership_store.role_of(user.user_id, org_id)
    if role != OrganizationRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires organization admin role",
        )
