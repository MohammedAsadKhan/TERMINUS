"""Tests for the organizations module — service, stores, and business rules."""

from __future__ import annotations

import pytest

from terminus.core.ids import UserId
from terminus.licensing.service import LicenseService
from terminus.orgs.models import OrganizationRole
from terminus.orgs.service import (
    ForbiddenError,
    LastAdminError,
    OrganizationService,
)
from terminus.orgs.store import MembershipStore, OrganizationStore


def _make_service(secret: str = "test-secret") -> OrganizationService:
    """Create an OrganizationService wired with in-memory stores."""
    return OrganizationService(
        org_store=OrganizationStore(),
        member_store=MembershipStore(),
        license_service=LicenseService(secret=secret),
    )


class TestCreateOrg:
    """Creating an organization."""

    def test_creator_becomes_admin(self) -> None:
        # Given a service
        svc = _make_service()
        creator = UserId("usr-creator")

        # When an org is created
        org = svc.create_org("Acme Corp", creator)

        # Then the creator is an admin
        assert org.name == "Acme Corp"
        assert org.org_id.startswith("org-")
        assert svc.role_of(org.org_id, creator) == OrganizationRole.ADMIN

    def test_org_gets_trial_license(self) -> None:
        svc = _make_service()
        org = svc.create_org("TestCo", UserId("usr-1"))
        assert org.license_ref is not None


class TestAddMember:
    """Adding members to an organization."""

    def test_admin_can_add_member(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        member = UserId("usr-member")
        org = svc.create_org("Acme", admin)

        m = svc.add_member(org.org_id, admin, member, OrganizationRole.MEMBER)

        assert m.user_id == member
        assert m.role == OrganizationRole.MEMBER

    def test_non_admin_cannot_add_member(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        member = UserId("usr-member")
        outsider = UserId("usr-outsider")
        org = svc.create_org("Acme", admin)
        svc.add_member(org.org_id, admin, member, OrganizationRole.MEMBER)

        with pytest.raises(ForbiddenError):
            svc.add_member(org.org_id, member, outsider, OrganizationRole.VIEWER)


class TestRemoveMember:
    """Removing members."""

    def test_admin_can_remove_member(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        member = UserId("usr-member")
        org = svc.create_org("Acme", admin)
        svc.add_member(org.org_id, admin, member, OrganizationRole.MEMBER)

        svc.remove_member(org.org_id, admin, member)

        assert svc.role_of(org.org_id, member) is None

    def test_cannot_remove_last_admin(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        org = svc.create_org("Acme", admin)

        with pytest.raises(LastAdminError):
            svc.remove_member(org.org_id, admin, admin)


class TestChangeRole:
    """Changing member roles."""

    def test_promote_member_to_admin(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        member = UserId("usr-member")
        org = svc.create_org("Acme", admin)
        svc.add_member(org.org_id, admin, member, OrganizationRole.MEMBER)

        svc.change_role(org.org_id, admin, member, OrganizationRole.ADMIN)

        assert svc.role_of(org.org_id, member) == OrganizationRole.ADMIN

    def test_cannot_demote_last_admin(self) -> None:
        svc = _make_service()
        admin = UserId("usr-admin")
        org = svc.create_org("Acme", admin)

        with pytest.raises(LastAdminError):
            svc.change_role(org.org_id, admin, admin, OrganizationRole.VIEWER)


class TestTenancyIsolation:
    """Cross-org data must never leak."""

    def test_users_see_only_their_orgs(self) -> None:
        svc = _make_service()
        user_a = UserId("usr-a")
        user_b = UserId("usr-b")

        org_a = svc.create_org("Org A", user_a)
        org_b = svc.create_org("Org B", user_b)

        orgs_for_a = svc.list_for_user(user_a)
        orgs_for_b = svc.list_for_user(user_b)

        assert len(orgs_for_a) == 1
        assert orgs_for_a[0].org_id == org_a.org_id
        assert len(orgs_for_b) == 1
        assert orgs_for_b[0].org_id == org_b.org_id

    def test_user_in_multiple_orgs(self) -> None:
        svc = _make_service()
        user = UserId("usr-shared")
        admin_a = UserId("usr-admin-a")
        admin_b = UserId("usr-admin-b")

        org_a = svc.create_org("A", admin_a)
        org_b = svc.create_org("B", admin_b)

        svc.add_member(org_a.org_id, admin_a, user, OrganizationRole.MEMBER)
        svc.add_member(org_b.org_id, admin_b, user, OrganizationRole.VIEWER)

        orgs = svc.list_for_user(user)
        org_ids = {o.org_id for o in orgs}
        assert org_a.org_id in org_ids
        assert org_b.org_id in org_ids
