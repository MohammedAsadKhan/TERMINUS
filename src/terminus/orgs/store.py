"""Memory-backed stores for organizations and memberships."""

from __future__ import annotations

import threading

from terminus.core.base import MemoryRepository, NotFoundError
from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import Membership, Organization, OrganizationRole


class OrganizationStore(MemoryRepository[Organization]):
    """Thread-safe in-memory store for organizations."""

    def _record_id(self, record: Organization) -> str:
        return record.org_id

    def list_all(self) -> list[Organization]:
        """Internal scheduler enumeration; never exposed without authorization."""
        with self._lock:
            return list(self._store.values())


class MembershipStore:
    """Thread-safe in-memory store for org memberships.

    Memberships are keyed by ``(org_id, user_id)`` since a user can only hold one
    role per organization. This is not a standard ``MemoryRepository`` because
    memberships are queried by user across orgs.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[OrgId, UserId], Membership] = {}
        self._lock = threading.Lock()

    def create(self, membership: Membership) -> Membership:
        """Add a membership. Raises ValueError if it already exists."""
        key = (membership.org_id, membership.user_id)
        with self._lock:
            if key in self._store:
                msg = (
                    f"User {membership.user_id} is already a member "
                    f"of org {membership.org_id}"
                )
                raise ValueError(msg)
            self._store[key] = membership
        return membership

    def get(self, org_id: OrgId, user_id: UserId) -> Membership:
        """Return a membership or raise NotFoundError."""
        key = (org_id, user_id)
        with self._lock:
            try:
                return self._store[key]
            except KeyError:
                msg = f"User {user_id} is not a member of org {org_id}"
                raise NotFoundError(msg) from None

    def delete(self, org_id: OrgId, user_id: UserId) -> None:
        """Remove a membership. Raises NotFoundError if missing."""
        key = (org_id, user_id)
        with self._lock:
            try:
                del self._store[key]
            except KeyError:
                msg = f"User {user_id} is not a member of org {org_id}"
                raise NotFoundError(msg) from None

    def update(self, membership: Membership) -> Membership:
        """Replace an existing membership. Raises NotFoundError if missing."""
        key = (membership.org_id, membership.user_id)
        with self._lock:
            if key not in self._store:
                msg = (
                    f"User {membership.user_id} is not a member "
                    f"of org {membership.org_id}"
                )
                raise NotFoundError(msg)
            self._store[key] = membership
        return membership

    def memberships_for(self, org_id: OrgId) -> list[Membership]:
        """Return all memberships belonging to an organization."""
        with self._lock:
            return [m for (oid, _), m in self._store.items() if oid == org_id]

    def role_of(
        self, first: OrgId | UserId, second: OrgId | UserId
    ) -> OrganizationRole | None:
        """Return the user's role in the org, or None if not a member."""
        with self._lock:
            m = self._store.get((first, second)) or self._store.get((second, first))  # type: ignore
            return m.role if m is not None else None

    def orgs_for_user(self, user_id: UserId) -> list[Membership]:
        """Return all memberships for a user across all organizations."""
        with self._lock:
            return [m for (_, uid), m in self._store.items() if uid == user_id]
