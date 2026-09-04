"""Organization and membership models for multi-tenancy."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from terminus.core.ids import OrgId, UserId


class OrganizationRole(StrEnum):
    """Role a user holds within an organization."""

    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class Organization(BaseModel):
    """A tenant organization on the platform."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    org_id: OrgId
    name: str
    created_at: datetime
    license_ref: str | None = None

    @property
    def id(self) -> OrgId:
        """Alias for org_id."""
        return self.org_id


class Membership(BaseModel):
    """Binds a user to an organization with a specific role."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    org_id: OrgId
    user_id: UserId
    role: OrganizationRole
