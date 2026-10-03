"""Configurable Multi-Tenant Policy Engine Models for TERMINUS."""

from __future__ import annotations

from pydantic import BaseModel, Field


class IpSuppressionRule(BaseModel):
    cidr_or_ip: str
    description: str
    enabled: bool = True


class CustomPolicyRule(BaseModel):
    rule_id: str
    name: str
    match_field: str  # e.g., "description", "rule_id", "mitre", "src_ip"
    match_pattern: str  # regex or string
    target_tier: str  # "IGNORE", "TRIAGE", "ESCALATE"
    reason: str
    enabled: bool = True


class TenantPolicyProfile(BaseModel):
    org_id: str
    min_triage_level: int = 5
    min_escalate_level: int = 10
    business_hours_only: bool = False
    ip_suppressions: list[IpSuppressionRule] = Field(default_factory=list)
    custom_rules: list[CustomPolicyRule] = Field(default_factory=list)
