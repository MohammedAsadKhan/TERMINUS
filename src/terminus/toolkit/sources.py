# File name: sources.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Typed observations and trusted resource bindings for investigation readers.

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
    # One piece of source data with its source ids and timestamp, as returned by a
    # reader.
    source_id: Id
    source_event_id: Id
    source_timestamp: datetime
    data: JsonValue


class ReadCollection(Contract):
    # Outcome of a reader call; its validator keeps the status consistent with
    # observations, coverage and truncation.
    status: Literal["ok", "empty", "partial", "unavailable", "unsupported", "error"]
    observations: tuple[ReadObservation, ...] = ()
    coverage: Literal["complete", "incomplete", "unknown"] = "unknown"
    truncated: bool = False
    gaps: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def honest_collection(self) -> ReadCollection:
        """Reject collections that claim more than they delivered: empty must be
        complete with no observations, failures carry no observations, and truncation
        requires partial status.
        """
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
    """Protocol for read-only evidence collection; implementations receive a validated
    query and a server-bound resource.
    """
    async def read(
        self, query: ReadQuery, resource: EndpointResource
    ) -> ReadCollection: ...
