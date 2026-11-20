# File name: storage.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: SQLite-backed organization and membership stores.

"""SQLite-backed organization and membership stores.

Both stores use the injected database, so service transactions include every
organization and membership write made on the current thread.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from typing import override

from terminus.core.base import NotFoundError, Repository
from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import Membership, Organization, OrganizationRole
from terminus.storage.db import Database


class SqliteOrganizationStore(Repository[Organization]):
    """Durable organizations with explicit tenant scope on every public read."""

    def __init__(self, db: Database | None = None) -> None:
        """Bind an optional database; the shared singleton is used when none is given."""
        self._db_override: Database | None = db

    @property
    def _db(self) -> Database:
        """Return the injected database, or the process-wide singleton."""
        return self._db_override if self._db_override is not None else Database.get_instance()

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        """Open a writer-locked transaction so service-level organization and membership
        writes commit or roll back together.
        """
        return self._db.transaction()

    @staticmethod
    def _record(row: Mapping[str, object]) -> Organization:
        """Convert a stored organization row into an Organization model."""
        return Organization.model_validate(
            {key: row[key] for key in ("org_id", "name", "created_at", "license_ref")}
        )

    @override
    def create(self, record: Organization, org_id: OrgId) -> Organization:
        """Insert an organization, requiring its ID to equal the tenant scope; a
        duplicate ID becomes ValueError.
        """
        if record.org_id != org_id:
            raise ValueError("Organization identity must match its tenant scope")
        try:
            self._db.execute(
                "INSERT INTO organizations (org_id, name, created_at, license_ref) VALUES (?, ?, ?, ?)",
                (
                    record.org_id,
                    record.name,
                    record.created_at.isoformat(),
                    record.license_ref,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Record {record.org_id} already exists in org {org_id}"
            ) from exc
        return record

    @override
    def get(self, record_id: str, org_id: OrgId) -> Organization:
        """Read an organization; an organization's tenant scope is its own ID, so any
        other record_id is reported as not found.
        """
        if str(record_id) != str(org_id):
            raise NotFoundError(f"Record {record_id} not found in org {org_id}")
        row = self._db.fetchone(
            "SELECT org_id, name, created_at, license_ref FROM organizations WHERE org_id = ?",
            (str(org_id),),
        )
        if row is None:
            raise NotFoundError(f"Record {record_id} not found in org {org_id}")
        return self._record(row)

    def update(self, record: Organization, org_id: OrgId) -> Organization:
        """Replace the stored organization fields, refusing a record whose ID is not the
        tenant scope.
        """
        if str(record.org_id) != str(org_id):
            raise NotFoundError(f"Record {record.org_id} not found in org {org_id}")
        cursor = self._db.execute(
            "UPDATE organizations SET name = ?, created_at = ?, license_ref = ? WHERE org_id = ?",
            (
                record.name,
                record.created_at.isoformat(),
                record.license_ref,
                str(org_id),
            ),
        )
        if cursor.rowcount == 0:
            raise NotFoundError(f"Record {record.org_id} not found in org {org_id}")
        return record

    def delete(self, record_id: str, org_id: OrgId) -> None:
        """Delete the organization, refusing any record_id other than the tenant scope."""
        if str(record_id) != str(org_id):
            raise NotFoundError(f"Record {record_id} not found in org {org_id}")
        cursor = self._db.execute(
            "DELETE FROM organizations WHERE org_id = ?",
            (str(org_id),),
        )
        if cursor.rowcount == 0:
            raise NotFoundError(f"Record {record_id} not found in org {org_id}")

    @override
    def list(self, org_id: OrgId) -> list[Organization]:
        """Return only the caller's own organization row (the tenant filter is the
        organization ID).
        """
        rows = self._db.fetchall(
            "SELECT org_id, name, created_at, license_ref FROM organizations WHERE org_id = ?",
            (org_id,),
        )
        return [self._record(row) for row in rows]

    def list_all(self) -> list[Organization]:
        """Internal scheduler enumeration; authorization belongs to the caller."""
        rows = self._db.fetchall(
            "SELECT org_id, name, created_at, license_ref FROM organizations ORDER BY rowid"
        )
        return [self._record(row) for row in rows]


class SqliteMembershipStore:
    """Durable memberships keyed strictly by (organization, user)."""

    def __init__(self, db: Database | None = None) -> None:
        """Bind an optional database; the shared singleton is used when none is given."""
        self._db_override: Database | None = db

    @property
    def _db(self) -> Database:
        """Return the injected database, or the process-wide singleton."""
        return self._db_override if self._db_override is not None else Database.get_instance()

    def transaction(self) -> AbstractContextManager[sqlite3.Connection]:
        """Open a writer-locked transaction so service-level organization and membership
        writes commit or roll back together.
        """
        return self._db.transaction()

    @staticmethod
    def _record(row: Mapping[str, object]) -> Membership:
        """Convert a stored membership row into a Membership model."""
        return Membership.model_validate(row)

    @staticmethod
    def _missing(org_id: OrgId, user_id: UserId) -> NotFoundError:
        """Build the NotFoundError used when a user has no membership in the
        organization.
        """
        return NotFoundError(f"User {user_id} is not a member of org {org_id}")

    def create(self, membership: Membership) -> Membership:
        """Insert a membership; a foreign-key failure means the organization or user
        does not exist, any other integrity error means the user is already a member.
        """
        try:
            self._db.execute(
                "INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)",
                (membership.org_id, membership.user_id, membership.role.value),
            )
        except sqlite3.IntegrityError as exc:
            if exc.sqlite_errorcode == sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY:
                raise NotFoundError(
                    f"Organization {membership.org_id} or user {membership.user_id} does not exist"
                ) from exc
            raise ValueError(
                f"User {membership.user_id} is already a member of org {membership.org_id}"
            ) from exc
        return membership

    def get(self, org_id: OrgId, user_id: UserId) -> Membership:
        """Read one membership by (organization, user) or raise NotFoundError."""
        row = self._db.fetchone(
            "SELECT org_id, user_id, role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        )
        if row is None:
            raise self._missing(org_id, user_id)
        return self._record(row)

    def delete(self, org_id: OrgId, user_id: UserId) -> None:
        """Delete one membership, raising NotFoundError when none matched."""
        cursor = self._db.execute(
            "DELETE FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        )
        if cursor.rowcount == 0:
            raise self._missing(org_id, user_id)

    def update(self, membership: Membership) -> Membership:
        """Change the stored role for an existing membership, raising NotFoundError when
        none matched.
        """
        cursor = self._db.execute(
            "UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?",
            (membership.role.value, membership.org_id, membership.user_id),
        )
        if cursor.rowcount == 0:
            raise self._missing(membership.org_id, membership.user_id)
        return membership

    def memberships_for(self, org_id: OrgId) -> list[Membership]:
        """List the memberships of one organization in insertion order."""
        rows = self._db.fetchall(
            "SELECT org_id, user_id, role FROM memberships WHERE org_id = ? ORDER BY rowid",
            (org_id,),
        )
        return [self._record(row) for row in rows]

    def role_of(self, org_id: OrgId, user_id: UserId) -> OrganizationRole | None:
        """Return the user's role in the organization, or None when not a member."""
        row = self._db.fetchone(
            "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, user_id),
        )
        return OrganizationRole(row["role"]) if row is not None else None

    def orgs_for_user(self, user_id: UserId) -> list[Membership]:
        """List a user's memberships across organizations in insertion order."""
        rows = self._db.fetchall(
            "SELECT org_id, user_id, role FROM memberships WHERE user_id = ? ORDER BY rowid",
            (user_id,),
        )
        return [self._record(row) for row in rows]
