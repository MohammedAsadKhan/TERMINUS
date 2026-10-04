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
