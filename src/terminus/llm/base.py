from __future__ import annotations

from typing import Protocol, TypeAlias, runtime_checkable

JsonValue: TypeAlias = (
    dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None
)


class LlmError(RuntimeError):
    pass


@runtime_checkable
class LlmClient(Protocol):
    async def respond_json(self, system: str, user: str) -> dict[str, JsonValue]: ...
