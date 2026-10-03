"""Blast-Radius Calculation & Critical Asset Protection Guardrails for TERMINUS 2.0.

Prevents automated or accidental disruption of Tier-0 critical enterprise infrastructure
(Domain Controllers, Payment Gateways, Core DNS) during automated incident containment.

Follows Decision D12: force_override bypasses ONLY critical hostname pattern checks,
never invalid targets, protected networks, gateways, or the org allowlist.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AssetCriticalityTier(StrEnum):
    TIER_0 = "TIER_0"  # Domain Controllers, DNS Root, Core Auth, Payment Switch
    TIER_1 = "TIER_1"  # Production DBs, Core APIs, Main Gateways
    TIER_2 = "TIER_2"  # Standard Worker nodes, Dev Servers, Staging
    TIER_3 = "TIER_3"  # End-user Workstations, Sandbox Containers


@dataclass
class BlastRadiusAssessment:
    allowed: bool
    reason: str | None
    target: str = ""
    asset_tier: AssetCriticalityTier = AssetCriticalityTier.TIER_3
    auto_containment_allowed: bool = True
    risk_score: float = 0.0

    @property
    def rationale(self) -> str:
        return self.reason or ""

    def __iter__(self):
        yield self.allowed
        yield self.reason


class ContainmentGuardrail:
    """Calculates blast radius and blocks high-risk or invalid containment actions."""

    CRITICAL_HOST_KEYWORDS = [
        "dc01",
        "dc02",
        "dc-",
        "domain-controller",
        "domain_controller",
        "activedirectory",
        "active-directory",
        "dns01",
        "k8s-master",
        "k8s_master",
        "core-db",
        "core_db",
        "payment",
        "prod-db",
        "prod_db",
        "prod-api",
        "prod_api",
        "gateway",
        "vault",
        "auth-service",
        "auth_service",
    ]

    PROTECTED_NETWORKS = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("127.0.0.0/8"),      # Loopback
        ipaddress.ip_network("169.254.0.0/16"),    # Link-local / Cloud metadata
        ipaddress.ip_network("224.0.0.0/4"),      # Multicast
        ipaddress.ip_network("255.255.255.255/32"),
        ipaddress.ip_network("10.0.0.0/24"),      # Core management subnet
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
    ]

    @classmethod
    def assess_target(
        cls,
        target: str,
        kind: str = "host",  # "host" or "ip"
        org_id: str = "default",
        allowlist_repo: Any = None,
        force_override: bool = False,
    ) -> BlastRadiusAssessment:
        """Assesses whether containment action against target is permissible."""
        if not target or not target.strip():
            return BlastRadiusAssessment(
                allowed=False,
                reason="Target identifier is empty or whitespace.",
                target=target,
                asset_tier=AssetCriticalityTier.TIER_0,
                auto_containment_allowed=False,
                risk_score=1.0,
            )

        target_str = target.strip()
        target_lower = target_str.lower()

        # 1. IP Parsing and Protected Subnet Checks
        try:
            ip_obj = ipaddress.ip_address(target_str)
            for net in cls.PROTECTED_NETWORKS:
                if ip_obj in net:
                    return BlastRadiusAssessment(
                        allowed=False,
                        reason=f"IP address {target_str} falls within protected/infrastructure network {net}.",
                        target=target_str,
                        asset_tier=AssetCriticalityTier.TIER_0,
                        auto_containment_allowed=False,
                        risk_score=1.0,
                    )
        except ValueError:
            if kind == "ip":
                return BlastRadiusAssessment(
                    allowed=False,
                    reason=f"Invalid IP address format: '{target_str}'.",
                    target=target_str,
                    asset_tier=AssetCriticalityTier.TIER_0,
                    auto_containment_allowed=False,
                    risk_score=1.0,
                )

        # 2. Org Allowlist Check (Cannot be overridden)
        if allowlist_repo is not None:
            try:
                if hasattr(allowlist_repo, "is_allowlisted"):
                    if allowlist_repo.is_allowlisted(org_id, target_str):
                        return BlastRadiusAssessment(
                            allowed=False,
                            reason=f"Target '{target_str}' is protected by organization allowlist policy.",
                            target=target_str,
                            asset_tier=AssetCriticalityTier.TIER_0,
                            auto_containment_allowed=False,
                            risk_score=1.0,
                        )
                elif isinstance(allowlist_repo, (set, list, tuple)):
                    if target_str in allowlist_repo or target_lower in allowlist_repo:
                        return BlastRadiusAssessment(
                            allowed=False,
                            reason=f"Target '{target_str}' is protected by organization allowlist policy.",
                            target=target_str,
                            asset_tier=AssetCriticalityTier.TIER_0,
                            auto_containment_allowed=False,
                            risk_score=1.0,
                        )
            except Exception as e:
                return BlastRadiusAssessment(
                    allowed=False,
                    reason=f"Allowlist verification failed due to internal error ({e}); failing closed for safety.",
                    target=target_str,
                    asset_tier=AssetCriticalityTier.TIER_0,
                    auto_containment_allowed=False,
                    risk_score=1.0,
                )

        # 3. Critical Hostname Pattern Check (Can be bypassed with force_override)
        if any(kw in target_lower for kw in cls.CRITICAL_HOST_KEYWORDS):
            if force_override:
                return BlastRadiusAssessment(
                    allowed=True,
                    reason=f"Critical asset protection overridden by administrator for '{target_str}'.",
                    target=target_str,
                    asset_tier=AssetCriticalityTier.TIER_1,
                    auto_containment_allowed=True,
                    risk_score=0.95,
                )
            else:
                return BlastRadiusAssessment(
                    allowed=False,
                    reason=f"Target '{target_str}' matches critical asset infrastructure keyword. Containment blocked.",
                    target=target_str,
                    asset_tier=AssetCriticalityTier.TIER_0,
                    auto_containment_allowed=False,
                    risk_score=0.95,
                )

        # 4. Standard Allowed Target
        return BlastRadiusAssessment(
            allowed=True,
            reason=None,
            target=target_str,
            asset_tier=AssetCriticalityTier.TIER_3,
            auto_containment_allowed=True,
            risk_score=0.1,
        )
