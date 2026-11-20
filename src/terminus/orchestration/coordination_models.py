# File name: coordination_models.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Explicit objective and delegation contracts for deterministic coordinators.

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


class CoordinationLimitError(ValueError):
    """Delegation exceeds a deterministic task, help, or catalog bound."""


class CoordinationContract(BaseModel):
    # Strict, immutable base for coordination contracts that rejects unknown fields.

    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )


class IncidentObjective(CoordinationContract):
    # Request to coordinate an incident objective across one to five distinct areas,
    # deduplicated
    # by idempotency_key.

    # Leave room for the durable JSON envelope in Task.objective (16 KiB).
    objective: Annotated[str, Field(min_length=1, max_length=12000, pattern=r"\S")]
    areas: Annotated[list[Area], Field(min_length=1, max_length=5)]
    priority: Annotated[int, Field(ge=0, le=1000)] = 100
    idempotency_key: Identifier

    @field_validator("areas")
    @classmethod
    def unique_areas(cls, value: list[Area]) -> list[Area]:
        """Reject duplicate areas in the request."""
        if len(value) != len(set(value)):
            raise ValueError("areas must be unique")
        return value


class SpecialistDefinition(CoordinationContract):
    # Maps a specialist role to the area it serves.

    role: Label
    area: Area


class AreaObjective(CoordinationContract):
    # Objective and roles delegated to a single area, optionally tied to a help request.

    area: Area
    objective: str
    roles: Annotated[list[Label], Field(max_length=24)]
    help_request_id: Identifier | None = None


class MainObjective(CoordinationContract):
    # The incident request together with its per-area plans (one to five).

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
        """Reject duplicate evidence kinds or evidence IDs."""
        if len(value) != len(set(value)):
            raise ValueError("items must be unique")
        return value
