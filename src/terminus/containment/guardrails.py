"""Blast-Radius Calculation & Critical Asset Protection Guardrails for TERMINUS 2.0.

Prevents automated or accidental disruption of Tier-0 critical enterprise infrastructure
(Domain Controllers, Payment Gateways, Core DNS) during automated incident containment.

Follows Decision D12: force_override bypasses ONLY critical hostname pattern checks,
never invalid targets, protected networks, gateways, or the org allowlist.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    ttl_seconds: int = 1800  # Default 30-minute auto-rollback lease
    expires_at: str = field(default_factory=lambda: (datetime.now(UTC) + timedelta(seconds=1800)).isoformat())

    @property
    def rationale(self) -> str:
        return self.reason or ""

    def __iter__(self):
        yield self.allowed
        yield self.reason


class FleetContainmentQuota:
    """Sliding-window containment rate limiter preventing self-inflicted enterprise DoS."""

    _lock = threading.Lock()
    _global_events: dict[str, list[float]] = {}   # org_id -> [timestamps]
    _subnet_events: dict[str, list[float]] = {}   # org_id:subnet -> [timestamps]

    MAX_GLOBAL_ISOLATIONS_PER_15MIN: int = 10
    MAX_SUBNET_ISOLATIONS_PER_15MIN: int = 3
    WINDOW_SECONDS: float = 900.0  # 15 minutes

    @classmethod
    def record_and_check(cls, org_id: str, target: str) -> tuple[bool, str | None]:
        """Checks whether the target containment exceeds global or subnet quotas."""
        now = time.time()
        window_start = now - cls.WINDOW_SECONDS

        with cls._lock:
            # 1. Clean and check global org window
            history = cls._global_events.setdefault(org_id, [])
            cls._global_events[org_id] = [t for t in history if t >= window_start]
            if len(cls._global_events[org_id]) >= cls.MAX_GLOBAL_ISOLATIONS_PER_15MIN:
                return False, f"Global containment quota exceeded ({len(cls._global_events[org_id])}/{cls.MAX_GLOBAL_ISOLATIONS_PER_15MIN} in 15m). Quorum approval required."

            # 2. Check subnet window if IP
            subnet_key = None
            try:
                ip_obj = ipaddress.ip_address(target.strip())
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    subnet_key = f"{org_id}:{ip_obj.exploded.rsplit('.', 1)[0]}.0/24"
            except Exception:
                pass

            if subnet_key:
                sub_history = cls._subnet_events.setdefault(subnet_key, [])
                cls._subnet_events[subnet_key] = [t for t in sub_history if t >= window_start]
                if len(cls._subnet_events[subnet_key]) >= cls.MAX_SUBNET_ISOLATIONS_PER_15MIN:
                    return False, f"Subnet containment quota exceeded ({len(cls._subnet_events[subnet_key])}/{cls.MAX_SUBNET_ISOLATIONS_PER_15MIN} in 15m for {subnet_key.split(':', 1)[1]}). Quorum approval required."

            # Record event
            cls._global_events[org_id].append(now)
            if subnet_key:
                cls._subnet_events[subnet_key].append(now)

            return True, None

    @classmethod
    def reset(cls) -> None:
        """Reset internal rate tracking state (useful for test fixtures)."""
        with cls._lock:
            cls._global_events.clear()
            cls._subnet_events.clear()


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
