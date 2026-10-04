"""Typed observations and trusted resource bindings for investigation readers."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, JsonValue, model_validator

from terminus.toolkit.models import Contract, Id, ReadQuery, Text


class EndpointResource(Contract):
    """Server policy mapping; never construct from model-supplied tool arguments."""

    org_id: Id
    resource_id: Id
    agent_id: str = Field(pattern=r"^[0-9]{3,8}$")


class ReadObservation(Contract):
    source_id: Id
    source_event_id: Id
    source_timestamp: datetime
    data: JsonValue


class ReadCollection(Contract):
    status: Literal["ok", "empty", "partial", "unavailable", "unsupported", "error"]
    observations: tuple[ReadObservation, ...] = ()
    coverage: Literal["complete", "incomplete", "unknown"] = "unknown"
    truncated: bool = False
    gaps: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def honest_collection(self) -> ReadCollection:
        if self.status == "empty" and (
            self.observations or self.coverage != "complete" or self.truncated
        ):
            raise ValueError("Empty requires complete collection")
        if self.status in {"unavailable", "unsupported", "error"} and self.observations:
            raise ValueError("Failed collection cannot supply observations")
        if self.truncated and self.status != "partial":
            raise ValueError("Truncation requires partial collection")
        return self


class InvestigationReader(Protocol):
    async def read(
        self, query: ReadQuery, resource: EndpointResource
    ) -> ReadCollection: ...
