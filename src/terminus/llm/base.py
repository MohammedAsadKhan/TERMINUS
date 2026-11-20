# File name: base.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Define the client interface and response data for legacy model calls.

from __future__ import annotations

from typing import Protocol, TypeAlias, runtime_checkable

JsonValue: TypeAlias = (
    dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None
)


# Failure of a model call; callers fall back to an explicit offline or fallback verdict.
class LlmError(RuntimeError):
    pass


@runtime_checkable
class LlmClient(Protocol):
    """Interface for a model client that answers a system and user prompt with a JSON object."""

    async def respond_json(self, system: str, user: str) -> dict[str, JsonValue]: ...
