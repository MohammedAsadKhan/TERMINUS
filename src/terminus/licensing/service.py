from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from terminus.core.base import Service
from terminus.core.ids import LicenseId, OrgId
from terminus.licensing.crypto import LicenseError, decode, encode
from terminus.licensing.models import Feature, License, LicenseTier
from terminus.licensing.tiers import MAX_SEATS_BY_TIER, features_for


class LicenseService(Service):
    """Service for managing software licenses."""

    def __init__(self, secret: str) -> None:
        """Initialize the license service with the given signing secret."""
        self._secret = secret

    def generate(
        self,
        org_id: OrgId,
        tier: LicenseTier,
        max_seats: int | None = None,
        seats: int | None = None,
        days: int = 365,
        duration_days: int | None = None,
    ) -> str:
        """Generate a new signed license token."""
        tier_max = MAX_SEATS_BY_TIER[tier]
        seat_val = seats if seats is not None else max_seats
        effective_seats = tier_max if seat_val is None else seat_val
        if effective_seats > tier_max:
            raise ValueError(
                f"Requested seats ({effective_seats}) exceeds maximum "
                f"for {tier} tier ({tier_max})",
            )

        effective_days = duration_days if duration_days is not None else days
        now = datetime.now(UTC)
        expires = now + timedelta(days=effective_days)

        license_obj = License(
            id=LicenseId(secrets.token_hex(16)),
            org_id=org_id,
            tier=tier,
            features=features_for(tier),
            max_seats=effective_seats,
            expires_at=expires,
            issued_at=now,
        )

        return encode(license_obj, self._secret)

    def validate(self, token: str) -> License:
        """Validate a license token and return the parsed license."""
        license_obj = decode(token, self._secret)

        now = datetime.now(UTC)
        if now > license_obj.expires_at:
            raise LicenseError("License has expired", reason="expired")

        return license_obj

    def entitled(self, license_obj: License, feature: Feature) -> bool:
        """Check if the given license is entitled to the specified feature."""
        now = datetime.now(UTC)
        if now > license_obj.expires_at:
            return False

        return feature in license_obj.features
