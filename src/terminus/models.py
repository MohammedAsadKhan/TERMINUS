"""Domain models and trust-boundary types for the agentic SOC pipeline.

All data that crosses a boundary (webhook JSON, LLM responses, API payloads) is parsed
into a Pydantic model here. Internal value objects are frozen dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field

from terminus.core.ids import AgentId, RuleId

# ─── Enums ─────────────────────────────────────────────────────────────────────────


class Severity(StrEnum):
    """Investigation verdict severity. Independent of the Wazuh alert level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How sure the agent is of its severity assessment."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Tier(StrEnum):
    """Action tier assigned by the policy engine.

    Tier 3 (Isolate) is designed for but intentionally not wired in MVP-1; it is the
    only tier that would require human approval.
    """

    IGNORE = "ignore"
    TRIAGE = "triage"
    ESCALATE = "escalate"
    ISOLATE = "isolate"


# ─── Trust-boundary models ─────────────────────────────────────────────────────────


class SiemAlert(BaseModel):
    """A Wazuh alert received over the webhook. Parsed at the HTTP boundary.

    Uses ``AliasChoices`` with ``AliasPath`` to handle both raw nested Wazuh JSON
    (``{"rule": {"id": 5710}}``) and flat pre-parsed dicts (``{"rule_id": 5710}``).

    Extra fields from Wazuh are preserved for downstream evidence gathering but the
    fields we rely on are validated and typed.
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    id: str = Field(
        validation_alias=AliasChoices("id", "alert_id"),
    )
    rule_id: RuleId = Field(
        validation_alias=AliasChoices(AliasPath("rule", "id"), "rule_id"),
    )
    level: int = Field(
        validation_alias=AliasChoices(AliasPath("rule", "level"), "level"),
    )
    description: str = Field(
        validation_alias=AliasChoices(
            AliasPath("rule", "description"),
            "description",
            "rule_description",
        ),
        default="",
    )

    @property
    def rule_description(self) -> str:
        return self.description
    mitre: str | None = Field(
        validation_alias=AliasChoices(
            AliasPath("rule", "mitre", "id"),
            "mitre",
        ),
        default=None,
    )
    agent_id: AgentId | None = Field(
        validation_alias=AliasChoices(AliasPath("agent", "id"), "agent_id"),
        default=None,
    )
    agent_name: str | None = Field(
        validation_alias=AliasChoices(AliasPath("agent", "name"), "agent_name"),
        default=None,
    )
    timestamp: str = ""
    location: str = ""
    hash: str | None = None
    src_ip: str | None = Field(
        validation_alias=AliasChoices(AliasPath("data", "srcip"), "src_ip"),
        default=None,
    )


class Verdict(BaseModel):
    """Structured output produced by the LLM investigation. Validated at the LLM boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    severity: Severity
    confidence: Confidence
    summary: str
    recommended_actions: list[str] = Field(default_factory=list)


class PolicyResult(BaseModel):
    """Output of the policy engine for one alert."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    alert_id: str
    tier: Tier
    should_investigate: bool
    reason: str


# ─── Internal value objects ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Evidence:
    """Evidence about an alert gathered by the agent before the LLM call."""

    alert: SiemAlert
    agent_name: str | None
    threat_intel: str
    context_notes: str


@dataclass(frozen=True, slots=True)
class InvestigationReport:
    """Final report for one investigated alert."""

    alert_id: str
    policy: PolicyResult
    verdict: Verdict
    evidence: Evidence
