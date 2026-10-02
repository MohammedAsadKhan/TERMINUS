"""Deterministic Sub-Millisecond Multi-Tenant Policy Engine for TERMINUS 2.0.

Provides high-speed, zero-token triage, per-tenant CIDR allowlists, and accurate
MITRE ATT&CK technique severity classification.
"""

from __future__ import annotations

import ipaddress
import re

from terminus.core.ids import OrgId
from terminus.models import PolicyResult, SiemAlert, Tier
from terminus.policies.models import TenantPolicyProfile


class PolicyEngine:
    """Evaluates alerts deterministically before LLM invocation."""

    # High-impact MITRE ATT&CK techniques requiring immediate Escalation
    CRITICAL_MITRE_PREFIXES = {
        "T1001",  # Data Obfuscation / C2 Communication
        "T1003",  # OS Credential Dumping (LSASS, SAM)
        "T1486",  # Data Encrypted for Impact (Ransomware)
        "T1190",  # Exploit Public-Facing Application (Log4Shell, RCE)
        "T1203",  # Exploitation for Client Execution
        "T1552",  # Unsecured Credentials (Honeytokens, AWS Keys)
        "T1567",  # Exfiltration Over Web Service
        "T1078",  # Valid Accounts Abuse (Unauthorized Admin Login)
        "T1059",  # Command & Scripting Interpreter (PowerShell, bash)
        "T1110",  # Brute Force
    }

    # Low-severity benign discovery techniques
    BENIGN_DISCOVERY_TECHNIQUES = {
        "T1082",  # System Information Discovery (uname, whoami)
        "T1033",  # System Owner/User Discovery
        "T1016",  # System Network Configuration Discovery (ipconfig)
        "T1049",  # System Network Connections Discovery (netstat)
    }

    def __init__(self, profiles: dict[str, TenantPolicyProfile] | None = None) -> None:
        self._profiles = profiles or {}

    def set_tenant_profile(self, profile: TenantPolicyProfile) -> None:
        self._profiles[profile.org_id] = profile

    def evaluate(self, alert: SiemAlert, org_id: OrgId | str) -> PolicyResult:
        """Sub-millisecond triage evaluation."""
        org_str = str(org_id)
        profile = self._profiles.get(org_str)

        level = alert.level
        min_triage = profile.min_triage_level if profile else 5
        min_escalate = profile.min_escalate_level if profile else 10

        # 1. Check IP Suppressions
        if profile and alert.src_ip:
            for rule in profile.ip_suppressions:
                if rule.enabled:
                    try:
                        net = ipaddress.ip_network(rule.cidr_or_ip, strict=False)
                        if ipaddress.ip_address(alert.src_ip) in net:
                            return PolicyResult(
                                alert_id=alert.id,
                                tier=Tier.IGNORE,
                                should_investigate=False,
                                reason=f"Source IP {alert.src_ip} suppressed by rule: {rule.description}",
                            )
                    except ValueError:
                        if alert.src_ip == rule.cidr_or_ip:
                            return PolicyResult(
                                alert_id=alert.id,
                                tier=Tier.IGNORE,
                                should_investigate=False,
                                reason=f"Source IP matched suppression: {rule.description}",
                            )

        # 2. Check Custom Matching Rules
        if profile:
            for custom in profile.custom_rules:
                if custom.enabled:
                    target_val = getattr(alert, custom.match_field, None) or ""
                    if re.search(custom.match_pattern, str(target_val), re.IGNORECASE):
                        target_tier = Tier(custom.target_tier.lower())
                        return PolicyResult(
                            alert_id=alert.id,
                            tier=target_tier,
                            should_investigate=(target_tier != Tier.IGNORE),
                            reason=f"Custom rule '{custom.name}' matched ({custom.reason})",
                        )

        # 3. MITRE ATT&CK Technique Severity Classification
        mitre_tag = (alert.mitre or "").upper().strip()
        is_mitre = mitre_tag.startswith("T")
        is_critical_mitre = any(mitre_tag.startswith(p) for p in self.CRITICAL_MITRE_PREFIXES)
        is_benign_discovery = any(mitre_tag.startswith(p) for p in self.BENIGN_DISCOVERY_TECHNIQUES)

        # 4. Deterministic Multi-Tier Logic
        if level >= min_escalate or is_critical_mitre:
            tier = Tier.ESCALATE
            should_investigate = True
            reason = (
                f"Critical MITRE technique '{mitre_tag}' detected"
                if is_critical_mitre
                else f"High alert severity level ({level} >= {min_escalate})"
            )
        elif is_benign_discovery and level < min_escalate:
            tier = Tier.IGNORE
            should_investigate = False
            reason = f"Benign administrative discovery technique '{mitre_tag}' filtered by policy"
        elif level >= min_triage or is_mitre:
            tier = Tier.TRIAGE
            should_investigate = True
            reason = f"Alert requires automated triage (Level: {level}, MITRE: {mitre_tag or 'None'})"
        else:
            tier = Tier.IGNORE
            should_investigate = False
            reason = f"Low alert level ({level} < {min_triage}), filtered by policy baseline"

        return PolicyResult(
            alert_id=alert.id,
            tier=tier,
            should_investigate=should_investigate,
            reason=reason,
        )
