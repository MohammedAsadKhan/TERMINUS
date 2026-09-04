"""Organization domain service enforcing business rules.

All operations require explicit ``org_id`` and ``actor`` (the user performing the action).
Cross-org access is structurally impossible — every method validates the actor's role
within the target organization.
"""

from __future__ import annotations

from datetime import UTC, datetime
from secrets import token_urlsafe

from terminus.core.base import NotFoundError, Service
from terminus.core.ids import OrgId, UserId
from terminus.licensing.models import License
from terminus.licensing.service import LicenseService
from terminus.licensing.tiers import MAX_SEATS_BY_TIER
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.store import MembershipStore, OrganizationStore


class ForbiddenError(ValueError):
    """Actor does not have the required role for this operation."""


class SeatLimitError(ValueError):
    """Organization has reached its licensed seat limit."""


class LastAdminError(ValueError):
    """Cannot remove or demote the last admin of an organization."""


class OrganizationService(Service):
    """Domain service for organization lifecycle and membership management."""

    def __init__(
        self,
        org_store: OrganizationStore,
        member_store: MembershipStore | None = None,
        license_service: LicenseService | None = None,
        membership_store: MembershipStore | None = None,
    ) -> None:
        self._orgs = org_store
        self._members = member_store or membership_store
        if self._members is None:
            raise TypeError(
                "OrganizationService requires member_store or membership_store"
            )
        if license_service is None:
            raise TypeError("OrganizationService requires license_service")
        self._licenses = license_service

    def create_org(
        self,
        name: str,
        creator: UserId | None = None,
        creator_id: UserId | None = None,
    ) -> Organization:
        """Create an organization. The creator becomes its first ADMIN.

        A TRIAL license is auto-issued (30 days, seats from tier defaults).
        """
        effective_creator = creator or creator_id
        if effective_creator is None:
            raise TypeError("create_org requires creator or creator_id")

        org_id = OrgId("org-" + token_urlsafe(8))
        now = datetime.now(UTC)

        # Issue a trial license for the new org.
        from terminus.licensing.models import LicenseTier

        trial_seats = MAX_SEATS_BY_TIER[LicenseTier.TRIAL]
        license_ref = self._licenses.generate(
            org_id=org_id,
            tier=LicenseTier.TRIAL,
            days=30,
            max_seats=trial_seats,
        )

        org = Organization(
            org_id=org_id,
            name=name,
            created_at=now,
            license_ref=license_ref,
        )
        self._orgs.create(org, org_id)

        # Creator becomes admin.
        membership = Membership(
            org_id=org_id,
            user_id=effective_creator,
            role=OrganizationRole.ADMIN,
        )
        self._members.create(membership)

        return org

    def _require_admin(self, org_id: OrgId, actor: UserId) -> None:
        """Raise ForbiddenError if actor is not an admin of the org."""
        role = self._members.role_of(org_id, actor)
        if role != OrganizationRole.ADMIN:
            msg = f"User {actor} is not an admin of org {org_id}"
            raise ForbiddenError(msg)

    def _admin_count(self, org_id: OrgId) -> int:
        """Return the number of admins in the organization."""
        members = self._members.memberships_for(org_id)
        return sum(1 for m in members if m.role == OrganizationRole.ADMIN)

    def add_member(
        self,
        org_id: OrgId,
        actor: UserId | None = None,
        user_id: UserId = UserId(""),
        role: OrganizationRole = OrganizationRole.MEMBER,
        actor_id: UserId | None = None,
    ) -> Membership:
        """Add a member to the organization. Actor must be ADMIN.

        Raises SeatLimitError if the org has reached its licensed seat limit.
        """
        effective_actor = actor or actor_id
        if effective_actor is None:
            raise TypeError("add_member requires actor or actor_id")

        self._require_admin(org_id, effective_actor)

        # Check seat limit from license.
        org = self._orgs.get(org_id, org_id)
        if org.license_ref:
            try:
                lic = self._licenses.validate(org.license_ref)
                current_members = self._members.memberships_for(org_id)
                if lic.max_seats > 0 and len(current_members) >= lic.max_seats:
                    msg = f"Org {org_id} has reached its seat limit of {lic.max_seats}"
                    raise SeatLimitError(msg)
            except Exception as exc:
                if isinstance(exc, SeatLimitError):
                    raise
                # License invalid/expired — still allow adding members in MVP.

        membership = Membership(org_id=org_id, user_id=user_id, role=role)
        return self._members.create(membership)

    def remove_member(
        self,
        org_id: OrgId,
        actor: UserId | None = None,
        user_id: UserId = UserId(""),
        actor_id: UserId | None = None,
    ) -> None:
        """Remove a member. Actor must be ADMIN. Cannot remove the last admin."""
        effective_actor = actor or actor_id
        if effective_actor is None:
            raise TypeError("remove_member requires actor or actor_id")

        self._require_admin(org_id, effective_actor)

        target = self._members.get(org_id, user_id)
        if target.role == OrganizationRole.ADMIN and self._admin_count(org_id) <= 1:
            msg = "Cannot remove the last admin of an organization"
            raise LastAdminError(msg)

        self._members.delete(org_id, user_id)

    def change_role(
        self,
        org_id: OrgId,
        actor: UserId | None = None,
        user_id: UserId = UserId(""),
        new_role: OrganizationRole = OrganizationRole.MEMBER,
        actor_id: UserId | None = None,
    ) -> Membership:
        """Change a member's role. Actor must be ADMIN. Cannot demote the last admin."""
        effective_actor = actor or actor_id
        if effective_actor is None:
            raise TypeError("change_role requires actor or actor_id")

        self._require_admin(org_id, effective_actor)

        current = self._members.get(org_id, user_id)
        if (
            current.role == OrganizationRole.ADMIN
            and new_role != OrganizationRole.ADMIN
            and self._admin_count(org_id) <= 1
        ):
            msg = "Cannot demote the last admin of an organization"
            raise LastAdminError(msg)

        updated = Membership(org_id=org_id, user_id=user_id, role=new_role)
        return self._members.update(updated)

    def role_of(self, org_id: OrgId, user_id: UserId) -> OrganizationRole | None:
        """Return the user's role in the organization, or None."""
        return self._members.role_of(org_id, user_id)

    def activate_license(
        self,
        org_id: OrgId,
        actor: UserId | None = None,
        raw_license: str | None = None,
        actor_id: UserId | None = None,
        token: str | None = None,
    ) -> License:
        """Activate a license for the organization. Actor must be ADMIN.

        Validates the license and checks that it belongs to this org.
        """
        effective_actor = actor or actor_id
        effective_token = raw_license or token
        if effective_actor is None or effective_token is None:
            raise TypeError(
                "activate_license requires actor/actor_id and token/raw_license"
            )

        self._require_admin(org_id, effective_actor)

        lic = self._licenses.validate(effective_token)
        if lic.org_id != org_id:
            from terminus.licensing.crypto import LicenseError

            msg = "License does not belong to this organization"
            raise LicenseError(msg)

        # Update org with new license ref.
        org = self._orgs.get(org_id, org_id)
        updated_org = Organization(
            org_id=org.org_id,
            name=org.name,
            created_at=org.created_at,
            license_ref=effective_token,
        )
        self._orgs.update(updated_org, org_id)
        return lic

    def list_for_user(self, user_id: UserId) -> list[Organization]:
        """Return all organizations the user is a member of."""
        memberships = self._members.orgs_for_user(user_id)
        orgs: list[Organization] = []
        for m in memberships:
            try:
                org = self._orgs.get(m.org_id, m.org_id)
                orgs.append(org)
            except NotFoundError:
                continue
        return orgs
