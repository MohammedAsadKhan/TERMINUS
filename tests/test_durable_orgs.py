"""Organizations and membership guards survive restart and concurrent writers."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

import pytest

from terminus.core.base import NotFoundError
from terminus.core.ids import OrgId, UserId
from terminus.licensing.models import LicenseTier
from terminus.licensing.service import LicenseService
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.orgs.service import LastAdminError, OrganizationService, SeatLimitError
from terminus.orgs.storage import SqliteMembershipStore, SqliteOrganizationStore
from terminus.storage.db import Database


def _service(db: Database) -> OrganizationService:
    return OrganizationService(
        SqliteOrganizationStore(db),
        SqliteMembershipStore(db),
        LicenseService("org-test"),
    )


def _user(db: Database, user_id: str) -> UserId:
    db.execute(
        "INSERT INTO users (user_id, email, password_hash, display_name, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            user_id,
            f"{user_id}@example.test",
            "test-hash",
            user_id,
            datetime.now(UTC).isoformat(),
        ),
    )
    return UserId(user_id)


def test_org_membership_and_license_survive_restart(tmp_path: Path) -> None:
    path = str(tmp_path / "orgs.sqlite")
    db = Database(path)
    admin, member = _user(db, "admin"), _user(db, "member")
    service = _service(db)
    org = service.create_org("Persistent", admin)
    service.add_member(org.org_id, admin, member, OrganizationRole.VIEWER)
    token = LicenseService("org-test").generate(
        org.org_id, LicenseTier.TRIAL, max_seats=2
    )
    activated = service.activate_license(org.org_id, admin, token)
    db.execute("SELECT 1").connection.close()

    restarted_db = Database(path)
    restarted = _service(restarted_db)
    persisted = SqliteOrganizationStore(restarted_db).get(org.org_id, org.org_id)
    assert persisted.name == org.name
    assert persisted.created_at == org.created_at
    assert persisted.license_ref == token
    assert persisted.license_ref is not None
    assert LicenseService("org-test").validate(persisted.license_ref) == activated
    assert restarted.role_of(org.org_id, admin) == OrganizationRole.ADMIN
    assert restarted.role_of(org.org_id, member) == OrganizationRole.VIEWER
    assert restarted.list_for_user(member) == [persisted]


def test_org_store_enforces_tenant_scope_and_crud(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "orgs.sqlite"))
    store = SqliteOrganizationStore(db)
    first = Organization(
        org_id=OrgId("first"), name="First", created_at=datetime.now(UTC)
    )
    second = Organization(
        org_id=OrgId("second"), name="Second", created_at=datetime.now(UTC)
    )
    store.create(first, first.org_id)
    store.create(second, second.org_id)
    assert store.list(first.org_id) == [first]
    assert store.list_all() == [first, second]
    with pytest.raises(NotFoundError):
        store.get(first.org_id, second.org_id)
    with pytest.raises(NotFoundError):
        store.update(first, second.org_id)
    with pytest.raises(NotFoundError):
        store.delete(first.org_id, second.org_id)
    with pytest.raises(ValueError):
        store.create(first, first.org_id)
    updated = first.model_copy(update={"name": "Renamed"})
    assert store.update(updated, first.org_id) == updated
    assert store.get(first.org_id, first.org_id) == updated
    store.delete(first.org_id, first.org_id)
    assert store.list(first.org_id) == []
    assert store.list_all() == [second]


def test_membership_scope_crud_and_unambiguous_role_lookup(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "orgs.sqlite"))
    orgs, members = SqliteOrganizationStore(db), SqliteMembershipStore(db)
    # Deliberately overlap user and organization strings: reversed lookup must
    # not grant a role belonging to a different identity pair.
    user = _user(db, "org-like-user")
    other = _user(db, "other")
    org = Organization(
        org_id=OrgId("user-like-org"), name="Org", created_at=datetime.now(UTC)
    )
    orgs.create(org, org.org_id)
    membership = Membership(
        org_id=org.org_id, user_id=user, role=OrganizationRole.ADMIN
    )
    assert members.create(membership) == membership
    assert members.get(org.org_id, user) == membership
    assert members.role_of(OrgId(user), UserId(org.org_id)) is None
    assert members.memberships_for(OrgId("elsewhere")) == []
    assert members.orgs_for_user(other) == []
    assert members.orgs_for_user(user) == [membership]
    with pytest.raises(ValueError):
        members.create(membership)
    with pytest.raises(NotFoundError):
        members.create(membership.model_copy(update={"user_id": UserId("unknown")}))
    with pytest.raises(NotFoundError):
        members.get(OrgId("elsewhere"), user)
    updated = membership.model_copy(update={"role": OrganizationRole.MEMBER})
    assert members.update(updated) == updated
    assert members.role_of(org.org_id, user) == OrganizationRole.MEMBER
    orgs.delete(org.org_id, org.org_id)
    assert members.orgs_for_user(user) == []
    with pytest.raises(NotFoundError):
        members.update(updated)
    with pytest.raises(NotFoundError):
        members.delete(org.org_id, user)


def test_create_org_rolls_back_when_creator_is_missing(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "orgs.sqlite"))
    with pytest.raises(NotFoundError, match="does not exist"):
        _service(db).create_org("No orphan organization", UserId("unknown"))
    assert SqliteOrganizationStore(db).list_all() == []
    assert db.fetchall("SELECT * FROM memberships") == []


@pytest.mark.parametrize("operation", ["remove", "demote"])
def test_concurrent_writers_preserve_last_admin(tmp_path: Path, operation: str) -> None:
    path = str(tmp_path / "orgs.sqlite")
    db = Database(path)
    first, second = _user(db, "first"), _user(db, "second")
    service = _service(db)
    org = service.create_org("Two administrators", first)
    service.add_member(org.org_id, first, second, OrganizationRole.ADMIN)
    services = [_service(Database(path)), _service(Database(path))]
    barrier = Barrier(2)

    def change(index: int) -> str:
        actor = (first, second)[index]
        barrier.wait(timeout=10)
        try:
            if operation == "remove":
                services[index].remove_member(org.org_id, actor, actor)
            else:
                services[index].change_role(
                    org.org_id, actor, actor, OrganizationRole.MEMBER
                )
        except LastAdminError:
            return "last-admin"
        return "changed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(change, range(2)))
    assert sorted(outcomes) == ["changed", "last-admin"]
    assert (
        sum(
            member.role == OrganizationRole.ADMIN
            for member in SqliteMembershipStore(db).memberships_for(org.org_id)
        )
        == 1
    )


def test_concurrent_admission_preserves_seat_limit(tmp_path: Path) -> None:
    path = str(tmp_path / "orgs.sqlite")
    db = Database(path)
    admin = _user(db, "admin")
    candidates = [_user(db, "one"), _user(db, "two")]
    service = _service(db)
    org = service.create_org("One available seat", admin)
    token = LicenseService("org-test").generate(
        org.org_id, LicenseTier.TRIAL, max_seats=2
    )
    service.activate_license(org.org_id, admin, token)
    services = [_service(Database(path)), _service(Database(path))]
    barrier = Barrier(2)

    def admit(index: int) -> str:
        barrier.wait(timeout=10)
        try:
            services[index].add_member(org.org_id, admin, candidates[index])
        except SeatLimitError:
            return "full"
        return "admitted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(admit, range(2)))
    assert sorted(outcomes) == ["admitted", "full"]
    assert len(SqliteMembershipStore(db).memberships_for(org.org_id)) == 2
