"""Explicit objective and delegation contracts for deterministic coordinators."""

from __future__ import annotations

from typing import Annotated, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from terminus.orchestration.models import Identifier, Label

Area = Literal[
    "alert_handling",
    "investigation",
    "infrastructure",
    "applications_data",
    "response_improvement",
]


CoreRole = Literal[
    "triage",
    "identity",
    "endpoint",
    "network",
    "response_planner",
    "verification",
    "evidence_reporting",
    "application_api",
]
EvidenceKind = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.:-]{0,63}$")]


class CoordinationContract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )


class IncidentObjective(CoordinationContract):
    # Leave room for the durable JSON envelope in Task.objective (16 KiB).
    objective: Annotated[str, Field(min_length=1, max_length=12000, pattern=r"\S")]
    areas: Annotated[list[Area], Field(min_length=1, max_length=5)]
    priority: Annotated[int, Field(ge=0, le=1000)] = 100
    idempotency_key: Identifier

    @field_validator("areas")
    @classmethod
    def unique_areas(cls, value: list[Area]) -> list[Area]:
        if len(value) != len(set(value)):
            raise ValueError("areas must be unique")
        return value


class SpecialistDefinition(CoordinationContract):
    role: Label
    area: Area


class AreaObjective(CoordinationContract):
    area: Area
    objective: str
    roles: Annotated[list[Label], Field(max_length=24)]
    help_request_id: Identifier | None = None


class MainObjective(CoordinationContract):
    request: IncidentObjective
    plans: Annotated[list[AreaObjective], Field(min_length=1, max_length=5)]


class HelpRequestSpec(CoordinationContract):
    """Bounded peer-help contract. Tenant, incident and requester role are
    derived server-side; there is no tool, scope, model or credential field."""

    target_role: CoreRole
    objective: Annotated[str, Field(min_length=1, max_length=1000, pattern=r"\S")]
    expected_evidence_kinds: Annotated[
        list[EvidenceKind], Field(default_factory=list, max_length=8)
    ]
    shared_evidence_ids: Annotated[
        list[Identifier], Field(default_factory=list, max_length=8)
    ]

    @field_validator("expected_evidence_kinds", "shared_evidence_ids")
    @classmethod
    def unique_items(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("items must be unique")
        return value
