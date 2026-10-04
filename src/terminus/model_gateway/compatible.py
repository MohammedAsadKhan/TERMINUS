"""Pure codec for OpenAI-compatible Chat Completions providers."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import JsonValue

from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
    parse_json_object,
    validate_response,
)

_OUTPUT_SCHEMA_NAME = "terminus_output"
CompatibleProvider = Literal[
    "openai",
    "openrouter",
    "deepseek",
    "openai_compatible",
    "local",
]
_COMPATIBLE_PROVIDERS = {
    "openai",
    "openrouter",
    "deepseek",
    "openai_compatible",
    "local",
}


class OpenAICompatibleCodec:
    """Encode and decode the conservative Chat Completions JSON subset."""

    def __init__(self, provider: CompatibleProvider = "openai_compatible") -> None:
        if provider not in _COMPATIBLE_PROVIDERS:
            raise ValueError("Unsupported OpenAI-compatible provider")
        self.provider: CompatibleProvider = provider
        self.headers: dict[str, str] = {}

    def path(self, request: ModelRequest) -> str:
        """Return the Chat Completions endpoint path."""
        _ = request
        return "/chat/completions"

    def encode(self, request: ModelRequest) -> dict[str, JsonValue]:
        """Encode a bounded request without performing any network I/O."""
        messages: list[JsonValue] = []
        system = _system_instruction(request, self.provider)
        if system:
            messages.append({"role": "system", "content": system})
        messages.extend(_encode_message(message) for message in request.messages)

        payload: dict[str, JsonValue] = {
            "model": request.model,
            "messages": messages,
            _token_parameter(self.provider): request.max_output_tokens,
        }
        if request.output_schema is not None:
            if self.provider == "deepseek":
                payload["response_format"] = {"type": "json_object"}
            else:
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": _OUTPUT_SCHEMA_NAME,
                        "strict": True,
                        "schema": request.output_schema,
                    },
                }
        if request.tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description,
                        "parameters": tool.parameters,
                    },
                }
                for tool in request.tools
            ]
        return payload

    def decode(  # noqa: C901
        self,
        payload: dict[str, JsonValue],
        request: ModelRequest,
    ) -> ModelResponse:
        """Decode one non-streaming response into the shared result contract."""
        if "error" in payload:
            raise ModelProtocolError("Compatible provider returned an error payload")

        model = _decode_model(payload.get("model"), request.model)
        usage = _decode_usage(payload.get("usage"))
        choice = _only_choice(payload.get("choices"))
        finish_reason = choice.get("finish_reason")
        if not isinstance(finish_reason, str) or not finish_reason:
            raise ModelProtocolError("Compatible response has no finish reason")
        if finish_reason not in {"stop", "length", "tool_calls", "content_filter"}:
            raise ModelProtocolError("Compatible response finish reason is unsupported")

        message = choice.get("message")
        if not isinstance(message, dict):
            raise ModelProtocolError("Compatible response has no assistant message")
        role = message.get("role")
        if role != "assistant":
            raise ModelProtocolError("Compatible response message role is invalid")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise ModelProtocolError("Compatible response content is invalid")

        refusal = message.get("refusal")
        if refusal is not None and not isinstance(refusal, str):
            raise ModelProtocolError("Compatible response refusal is invalid")
        if refusal or finish_reason == "content_filter":
            return validate_response(
                ModelResponse(
                    status="refused",
                    model=model,
                    usage=usage,
                    finish_reason=finish_reason,
                ),
                request,
            )

        if finish_reason == "length":
            return validate_response(
                ModelResponse(
                    status="incomplete",
                    model=model,
                    usage=usage,
                    finish_reason=finish_reason,
                ),
                request,
            )

        if finish_reason == "tool_calls":
            calls = _decode_tool_calls(message.get("tool_calls"))
            return validate_response(
                ModelResponse(
                    status="tool_calls",
                    model=model,
                    tool_calls=calls,
                    usage=usage,
                    finish_reason=finish_reason,
                ),
                request,
            )

        if message.get("tool_calls") not in (None, []):
            raise ModelProtocolError("Compatible response has inconsistent tool calls")

        if not isinstance(content, str):
            raise ModelProtocolError("Compatible response content is invalid")
        output = parse_json_object(content)
        return validate_response(
            ModelResponse(
                status="ok",
                model=model,
                output=output,
                usage=usage,
                finish_reason=finish_reason,
            ),
            request,
        )


def _system_instruction(request: ModelRequest, provider: CompatibleProvider) -> str:
    if provider != "deepseek" or request.output_schema is None:
        return request.system
    schema = json.dumps(
        request.output_schema,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    requirement = (
        "Return only one JSON object that exactly matches this JSON Schema: " + schema
    )
    return "\n\n".join(part for part in (request.system, requirement) if part)


def _token_parameter(provider: CompatibleProvider) -> str:
    return "max_completion_tokens" if provider == "openai" else "max_tokens"


def _encode_message(message: ChatMessage) -> JsonValue:
    if message.role == "user":
        return {"role": "user", "content": message.content}
    if message.role == "assistant":
        encoded: dict[str, JsonValue] = {
            "role": "assistant",
            "content": message.content,
        }
        if message.tool_calls:
            encoded["tool_calls"] = [
                _encode_tool_call(call) for call in message.tool_calls
            ]
        return encoded
    if message.role == "tool":
        if not message.tool_call_id:
            raise ModelProtocolError("Tool result has no call identifier")
        return {
            "role": "tool",
            "content": message.content,
            "tool_call_id": message.tool_call_id,
        }
    raise ModelProtocolError("Compatible request contains an unsupported message role")


def _encode_tool_call(call: ToolCall) -> JsonValue:
    if call.provider_state:
        raise ModelProtocolError("Compatible tool calls cannot carry provider state")
    try:
        arguments = json.dumps(
            call.arguments,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ModelProtocolError("Tool call arguments are not valid JSON") from exc
    return {
        "id": call.call_id,
        "type": "function",
        "function": {"name": call.name, "arguments": arguments},
    }


def _decode_model(value: JsonValue | None, fallback: str) -> str:
    if value is None or value == "":
        return fallback
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ModelProtocolError("Compatible response model is invalid")
    return value


def _decode_usage(value: JsonValue | None) -> ModelUsage:
    if value is None:
        return ModelUsage()
    if not isinstance(value, dict):
        raise ModelProtocolError("Compatible response usage is invalid")
    try:
        input_tokens = _token_count(value, "prompt_tokens")
        hit = _token_count(value, "prompt_cache_hit_tokens")  # DeepSeek direct
        miss = _token_count(value, "prompt_cache_miss_tokens")
        cached = _detail_count(value, "prompt_tokens_details", "cached_tokens")
        if cached is None:
            cached = hit
        elif hit is not None and hit != cached:
            raise ModelProtocolError("Compatible response token usage is invalid")
        if input_tokens is None and hit is not None and miss is not None:
            input_tokens = hit + miss
        # OpenAI/DeepSeek completion_tokens already include reasoning tokens.
        return ModelUsage(
            input_tokens=input_tokens,
            output_tokens=_token_count(value, "completion_tokens"),
            total_tokens=_token_count(value, "total_tokens"),
            cached_input_tokens=cached,
            reasoning_tokens=_detail_count(
                value, "completion_tokens_details", "reasoning_tokens"
            ),
        )
    except ValueError as exc:
        raise ModelProtocolError("Compatible response token usage is invalid") from exc


def _detail_count(usage: dict[str, JsonValue], group: str, key: str) -> int | None:
    details = usage.get(group)
    if details is None:
        return None
    if not isinstance(details, dict):
        raise ModelProtocolError("Compatible response token usage is invalid")
    return _token_count(details, key)


def _token_count(usage: dict[str, JsonValue], key: str) -> int | None:
    value = usage.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ModelProtocolError("Compatible response token usage is invalid")
    return value


def _only_choice(value: JsonValue | None) -> dict[str, JsonValue]:
    if not isinstance(value, list) or len(value) != 1:
        raise ModelProtocolError("Compatible response must contain exactly one choice")
    choice = value[0]
    if not isinstance(choice, dict):
        raise ModelProtocolError("Compatible response choice is invalid")
    return choice


def _decode_tool_calls(value: JsonValue | None) -> tuple[ToolCall, ...]:
    if not isinstance(value, list) or not value or len(value) > 8:
        raise ModelProtocolError("Compatible response has no tool calls")
    calls: list[ToolCall] = []
    for raw_call in value:
        if not isinstance(raw_call, dict) or raw_call.get("type") != "function":
            raise ModelProtocolError("Compatible response tool call is invalid")
        call_id = raw_call.get("id")
        function = raw_call.get("function")
        if not isinstance(call_id, str) or not isinstance(function, dict):
            raise ModelProtocolError("Compatible response tool call is invalid")
        name = function.get("name")
        arguments_text = function.get("arguments")
        if not isinstance(name, str) or not isinstance(arguments_text, str):
            raise ModelProtocolError("Compatible response tool call is invalid")
        try:
            arguments = parse_json_object(arguments_text)
        except ModelProtocolError as exc:
            raise ModelProtocolError(
                "Compatible response tool arguments are invalid"
            ) from exc
        try:
            calls.append(
                ToolCall(
                    call_id=call_id,
                    name=name,
                    arguments=arguments,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ModelProtocolError(
                "Compatible response tool call is invalid"
            ) from exc
    return tuple(calls)
