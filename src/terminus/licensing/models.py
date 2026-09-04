from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from terminus.core.ids import LicenseId, OrgId


class LicenseTier(StrEnum):
    """Available license tiers."""

    TRIAL = "trial"
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class Feature(StrEnum):
    """Features that can be enabled by a license."""

    API_ACCESS = "api_access"
    CUSTOM_RULES = "custom_rules"
    SSO = "sso"
    AUDIT_LOGS = "audit_logs"


class License(BaseModel):
    """A signed license issued to an organization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: LicenseId
    org_id: OrgId
    tier: LicenseTier
    features: list[Feature]
    max_seats: int
    expires_at: datetime
    issued_at: datetime

    @property
    def seats(self) -> int:
        """Alias for max_seats."""
        return self.max_seats
