from __future__ import annotations

from terminus.licensing.models import Feature, LicenseTier

TIER_FEATURES: dict[LicenseTier, frozenset[Feature]] = {
    LicenseTier.TRIAL: frozenset(),
    LicenseTier.FREE: frozenset(),
    LicenseTier.PRO: frozenset(
        {
            Feature.API_ACCESS,
            Feature.CUSTOM_RULES,
        }
    ),
    LicenseTier.ENTERPRISE: frozenset(
        {
            Feature.API_ACCESS,
            Feature.CUSTOM_RULES,
            Feature.SSO,
            Feature.AUDIT_LOGS,
        }
    ),
}


def features_for(tier: LicenseTier) -> list[Feature]:
    """Get the sorted list of features for a tier."""
    return sorted(TIER_FEATURES[tier])


MAX_SEATS_BY_TIER: dict[LicenseTier, int] = {
    LicenseTier.TRIAL: 3,
    LicenseTier.FREE: 5,
    LicenseTier.PRO: 50,
    LicenseTier.ENTERPRISE: 10000,
}
