"""Blast-Radius Calculation & Critical Asset Protection Guardrails for TERMINUS 2.0.

Prevents automated or accidental disruption of Tier-0 critical enterprise infrastructure
(Domain Controllers, Payment Gateways, Core DNS) during automated incident containment.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum


class AssetCriticalityTier(StrEnum):
    TIER_0 = "TIER_0"  # Domain Controllers, DNS Root, Core Auth, Payment Switch (Never auto-isolate)
    TIER_1 = "TIER_1"  # Production DBs, Core APIs, Main Gateways (Requires Dual Approval)
    TIER_2 = "TIER_2"  # Standard Worker nodes, Dev Servers, Staging
    TIER_3 = "TIER_3"  # End-user Workstations, Sandbox Containers


@dataclass
class BlastRadiusAssessment:
    target: str
    asset_tier: AssetCriticalityTier
    auto_containment_allowed: bool
    requires_dual_approval: bool
    risk_score: float  # 0.0 to 1.0 (Higher = more dangerous to isolate)
    rationale: str


class ContainmentGuardrail:
    """Calculates blast radius and blocks high-risk containment actions."""

    TIER_0_KEYWORDS = ["dc01", "dc02", "domain-controller", "activedirectory", "dns01", "k8s-master", "core-db", "payment"]
    TIER_1_KEYWORDS = ["prod-db", "prod-api", "gateway", "vault", "auth-service"]

    PROTECTED_SUBNETS = [
        ipaddress.ip_network("10.0.0.0/24"),  # Core management subnet
        ipaddress.ip_network("127.0.0.0/8"),   # Loopback
    ]

    @classmethod
    def assess_target(cls, target_name_or_ip: str) -> BlastRadiusAssessment:
        target_lower = target_name_or_ip.lower().strip()

        # Check IP protection
        try:
            ip_obj = ipaddress.ip_address(target_lower)
            for subnet in cls.PROTECTED_SUBNETS:
                if ip_obj in subnet:
                    return BlastRadiusAssessment(
                        target=target_name_or_ip,
                        asset_tier=AssetCriticalityTier.TIER_0,
                        auto_containment_allowed=False,
                        requires_dual_approval=True,
                        risk_score=0.99,
                        rationale=f"IP {target_name_or_ip} is in protected core infrastructure subnet {subnet}.",
                    )
        except ValueError:
            pass

        # Check Hostname Keywords
        if any(kw in target_lower for kw in cls.TIER_0_KEYWORDS):
            return BlastRadiusAssessment(
                target=target_name_or_ip,
                asset_tier=AssetCriticalityTier.TIER_0,
                auto_containment_allowed=False,
                requires_dual_approval=True,
                risk_score=0.95,
                rationale=f"Target '{target_name_or_ip}' identified as Tier-0 Critical Asset. Automated containment blocked.",
            )

        if any(kw in target_lower for kw in cls.TIER_1_KEYWORDS):
            return BlastRadiusAssessment(
                target=target_name_or_ip,
                asset_tier=AssetCriticalityTier.TIER_1,
                auto_containment_allowed=False,
                requires_dual_approval=True,
                risk_score=0.75,
                rationale=f"Target '{target_name_or_ip}' identified as Tier-1 Production Service. Requires dual approval.",
            )

        # Standard Endpoint / Workstation
        return BlastRadiusAssessment(
            target=target_name_or_ip,
            asset_tier=AssetCriticalityTier.TIER_3,
            auto_containment_allowed=True,
            requires_dual_approval=False,
            risk_score=0.15,
            rationale=f"Target '{target_name_or_ip}' is an endpoint/workstation. Safe for standard containment.",
        )
