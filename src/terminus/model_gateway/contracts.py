"""Bounded provider-neutral protocol contracts; no execution authorization."""

from __future__ import annotations

import json
import math
from typing import Annotated, ClassVar, Literal, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    model_validator,
)

_JSON: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class ModelProtocolError(ValueError):
    """Protocol failure safe for audit, without provider body or prompt text."""


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True
    )


def bounded_json(value: object, limit: int = 65536) -> None:
    try:
        encoded = json.dumps(value, allow_nan=False, ensure_ascii=True).encode()
        if len(encoded) > limit:
            raise ValueError
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ModelProtocolError("Invalid or oversized JSON") from None


def _pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    output: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in output:
            raise ModelProtocolError("Duplicate JSON property")
        output[key] = value
    return output


def parse_json_object(content: str, *, limit: int = 65536) -> dict[str, JsonValue]:
    if type(limit) is not int or not 1 <= limit <= 1048576:
        raise ModelProtocolError("Invalid JSON bound")
    if len(content.encode("utf-8")) > limit:
        raise ModelProtocolError("Oversized structured output")
    try:
        parsed: object = json.loads(content, object_pairs_hook=_pairs)  # pyright: ignore[reportAny] - stdlib JSON parsed then strictly revalidated
        result = _JSON.validate_python(parsed, strict=True)
        if not isinstance(result, dict):
            raise ValueError
        bounded_json(result, limit)
        return result
    except (ValueError, TypeError, RecursionError):
        raise ModelProtocolError("Invalid structured JSON") from None


def validate_schema(schema: dict[str, JsonValue], depth: int = 0) -> None:  # noqa: C901, PLR0912
    bounded_json(schema, 16384)
    if depth > 8 or set(schema) - {
        "type",
        "description",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "enum",
    }:
        raise ModelProtocolError("Unsupported schema dialect")
    kind = schema.get("type")
    if not isinstance(kind, str) or kind not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        raise ModelProtocolError("Unsupported schema type")
    if "description" in schema and not isinstance(schema["description"], str):
        raise ModelProtocolError("Invalid schema description")
    if kind == "object":
        properties = schema.get("properties")
        required = schema.get("required")
        if (
            not isinstance(properties, dict)
            or len(properties) > 32
            or not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
        ):
            raise ModelProtocolError("Invalid object schema")
        if (
            set(required) != set(properties)
            or len(required) != len(set(required))
            or schema.get("additionalProperties") is not False
        ):
            raise ModelProtocolError("Object schemas must be closed and fully required")
        for child in properties.values():
            if not isinstance(child, dict):
                raise ModelProtocolError("Invalid property schema")
            validate_schema(child, depth + 1)
    elif kind == "array":
        child = schema.get("items")
        if not isinstance(child, dict):
            raise ModelProtocolError("Array schema requires items")
        validate_schema(child, depth + 1)
    if kind != "object" and set(schema) & {
        "properties",
        "required",
        "additionalProperties",
    }:
        raise ModelProtocolError("Schema keywords do not match type")
    if kind != "array" and "items" in schema:
        raise ModelProtocolError("Schema keywords do not match type")
    if "enum" in schema:
        values = schema["enum"]
        if not isinstance(values, list) or not values or len(values) > 32:
            raise ModelProtocolError("Invalid enum")
        plain = {key: value for key, value in schema.items() if key != "enum"}
        for value in values:
            validate_value(value, plain)


def validate_value(value: JsonValue, schema: dict[str, JsonValue]) -> None:
    kind = schema["type"]
    valid = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": type(value) is int,
        "number": type(value) is int or (type(value) is float and math.isfinite(value)),
        "boolean": type(value) is bool,
        "null": value is None,
    }
    if not valid.get(str(kind), False):
        raise ModelProtocolError("Value does not match schema")
    if "enum" in schema and not any(
        type(value) is type(item) and value == item
        for item in cast("list[JsonValue]", schema["enum"])
    ):
        raise ModelProtocolError("Value does not match enum")
    if isinstance(value, dict):
        properties = cast("dict[str, JsonValue]", schema["properties"])
        if set(value) != set(properties):
            raise ModelProtocolError("Object properties do not match schema")
        for key, item in value.items():
            validate_value(item, cast("dict[str, JsonValue]", properties[key]))
    elif isinstance(value, list):
        for item in value:
            validate_value(item, cast("dict[str, JsonValue]", schema["items"]))


Name = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]


class ToolSpec(_Contract):
    name: Name
    description: str = Field(default="", max_length=1024)
    parameters: dict[str, JsonValue]

    @model_validator(mode="after")
    def schema_contract(self) -> ToolSpec:
        validate_schema(self.parameters)
        if self.parameters.get("type") != "object":
            raise ModelProtocolError("Tool schema must be an object")
        return self


class ToolCall(_Contract):
    call_id: Identifier
    name: Name
    arguments: dict[str, JsonValue]
    provider_state: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bounded_arguments(self) -> ToolCall:
        bounded_json(self.arguments, 16384)
        if set(self.provider_state) - {"thought_signature"} or any(
            not value or len(value.encode()) > 16384
            for value in self.provider_state.values()
        ):
            raise ModelProtocolError("Invalid opaque provider state")
        return self


class ChatMessage(_Contract):
    role: Literal["user", "assistant", "tool"]
    content: str = Field(default="", max_length=32768)
    tool_calls: tuple[ToolCall, ...] = Field(default=(), max_length=8)
    tool_call_id: Identifier | None = None
    tool_name: Name | None = None

    @model_validator(mode="after")
    def role_fields(self) -> ChatMessage:
        if self.role != "assistant" and self.tool_calls:
            raise ModelProtocolError("Only assistant messages may request tools")
        if self.role == "tool":
            if not self.tool_call_id or not self.tool_name or self.tool_calls:
                raise ModelProtocolError("Tool result requires matching identity")
            _ = parse_json_object(self.content)
        elif self.tool_call_id is not None or self.tool_name is not None:
            raise ModelProtocolError("Unexpected tool result identity")
        if not self.content and not self.tool_calls:
            raise ModelProtocolError("Empty chat message")
        return self


class ModelRequest(_Contract):
    model: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
    system: str = Field(default="", max_length=32768)
    messages: tuple[ChatMessage, ...] = Field(min_length=1, max_length=64)
    output_schema: dict[str, JsonValue] | None = None
    tools: tuple[ToolSpec, ...] = Field(default=(), max_length=16)
    max_output_tokens: int = Field(default=1024, ge=1, le=4096)

    @model_validator(mode="after")
    def request_contract(self) -> ModelRequest:  # noqa: C901
        bounded_json(self.model_dump(mode="json"))
        if self.output_schema is not None:
            validate_schema(self.output_schema)
            if self.output_schema.get("type") != "object":
                raise ModelProtocolError("Output schema must be an object")
        tools = {tool.name: tool for tool in self.tools}
        if len(tools) != len(self.tools) or self.messages[0].role != "user":
            raise ModelProtocolError("Invalid request tools or initial message")
        seen: set[str] = set()
        pending: dict[str, str] = {}
        for message in self.messages:
            if message.role == "tool":
                if pending.pop(message.tool_call_id or "", None) != message.tool_name:
                    raise ModelProtocolError("Unmatched tool result")
            else:
                if pending:
                    raise ModelProtocolError("Missing tool results")
                for call in message.tool_calls:
                    if call.call_id in seen or call.name not in tools:
                        raise ModelProtocolError("Unknown or duplicate tool call")
                    validate_value(call.arguments, tools[call.name].parameters)
                    seen.add(call.call_id)
                    pending[call.call_id] = call.name
        if pending or self.messages[-1].role == "assistant":
            raise ModelProtocolError("Request requires a user or completed tool turn")
        return self


class ModelUsage(_Contract):
    input_tokens: int | None = Field(default=None, ge=0, le=1000000000)
    output_tokens: int | None = Field(default=None, ge=0, le=1000000000)
    total_tokens: int | None = Field(default=None, ge=0, le=1000000000)
    cached_input_tokens: int | None = Field(default=None, ge=0, le=1000000000)
    reasoning_tokens: int | None = Field(default=None, ge=0, le=1000000000)

    # Convention (adapters normalize to it; None means unknown, never 0):
    # input_tokens = ALL prompt tokens including cached; cached_input_tokens =
    # the subset served from cache; output_tokens = ALL generated tokens
    # including reasoning; reasoning_tokens = the subset spent on reasoning.
    @model_validator(mode="after")
    def subsets_within_totals(self) -> ModelUsage:
        if (
            self.cached_input_tokens is not None
            and self.input_tokens is not None
            and self.cached_input_tokens > self.input_tokens
        ):
            raise ValueError("cached_input_tokens exceeds input_tokens")
        if (
            self.reasoning_tokens is not None
            and self.output_tokens is not None
            and self.reasoning_tokens > self.output_tokens
        ):
            raise ValueError("reasoning_tokens exceeds output_tokens")
        return self


class ModelResponse(_Contract):
    status: Literal["ok", "tool_calls", "refused", "incomplete", "error"]
    model: str = Field(min_length=1, max_length=128)
    output: dict[str, JsonValue] | None = None
    tool_calls: tuple[ToolCall, ...] = Field(default=(), max_length=8)
    usage: ModelUsage = Field(default_factory=ModelUsage)
    finish_reason: str | None = Field(default=None, max_length=128)
    error_code: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def result_contract(self) -> ModelResponse:
        bounded_json(self.model_dump(mode="json"))
        if self.status == "ok":
            if self.output is None or self.tool_calls:
                raise ModelProtocolError("Successful output must be structured JSON")
        elif self.status == "tool_calls":
            if not self.tool_calls or self.output is not None:
                raise ModelProtocolError("Tool output must contain only tool calls")
        elif self.output is not None or self.tool_calls:
            raise ModelProtocolError("Unsuccessful results cannot publish output")
        return self


def validate_response(response: ModelResponse, request: ModelRequest) -> ModelResponse:
    response = ModelResponse.model_validate(response.model_dump())
    if response.output is not None and request.output_schema is not None:
        validate_value(response.output, request.output_schema)
    tools = {tool.name: tool for tool in request.tools}
    previous = {
        call.call_id for message in request.messages for call in message.tool_calls
    }
    seen: set[str] = set()
    for call in response.tool_calls:
        if call.name not in tools or call.call_id in seen or call.call_id in previous:
            raise ModelProtocolError("Unknown or duplicate returned tool call")
        validate_value(call.arguments, tools[call.name].parameters)
        seen.add(call.call_id)
    return response
