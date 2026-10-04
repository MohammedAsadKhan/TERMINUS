"""Pure codecs for provider-native model APIs.

The codecs translate bounded shared contracts to and from provider JSON. They do
not perform I/O, resolve credentials, or infer provider capabilities.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import ClassVar, cast
from urllib.parse import quote

from pydantic import JsonValue, ValidationError

from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
    bounded_json,
    parse_json_object,
    validate_response,
)

_ERROR_CODE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")
_GEMINI_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_MAX_TOOL_CALLS = 8


def _object(value: object, message: str = "Malformed provider response") -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ModelProtocolError(message)
    raw = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in raw):
        raise ModelProtocolError(message)
    return cast("dict[str, JsonValue]", value)


def _array(value: object, message: str = "Malformed provider response") -> list[JsonValue]:
    if not isinstance(value, list):
        raise ModelProtocolError(message)
    return cast("list[JsonValue]", value)


def _string(value: object, message: str = "Malformed provider response") -> str:
    if not isinstance(value, str):
        raise ModelProtocolError(message)
    return value


def _optional_count(container: dict[str, JsonValue], key: str) -> int | None:
    if key not in container:
        return None
    value = container[key]
    if type(value) is not int or value < 0 or value > 1_000_000_000:
        raise ModelProtocolError("Invalid provider usage")
    return value


def _drop_nulls(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {key: value for key, value in payload.items() if value is not None}


def _usage(
    payload: dict[str, JsonValue],
    *,
    input_key: str,
    output_key: str,
    total_key: str | None = None,
    provider: str = "",
) -> ModelUsage:
    # Normalized to ModelUsage convention: input/output include cached/reasoning.
    input_tokens = _optional_count(payload, input_key)
    output_tokens = _optional_count(payload, output_key)
    total_tokens = _optional_count(payload, total_key) if total_key else None
    cached: int | None = None
    reasoning: int | None = None
    if provider == "anthropic":
        # Anthropic input_tokens EXCLUDES cache read/creation tokens; output
        # includes thinking but has no separate reasoning count (stays None).
        # Explicit JSON null is treated as absent (unknown).
        read = _optional_count(_drop_nulls(payload), "cache_read_input_tokens")
        creation = _optional_count(_drop_nulls(payload), "cache_creation_input_tokens")
        cached = read
        if read is None and creation is None:
            pass  # no cache information: reported input_tokens is unambiguous
        elif read is None or creation is None or input_tokens is None:
            input_tokens = None  # a needed component is unknown
        else:
            input_tokens = input_tokens + read + creation
    elif provider == "gemini":
        # Gemini candidatesTokenCount EXCLUDES thoughtsTokenCount.
        cached = _optional_count(payload, "cachedContentTokenCount")
        reasoning = _optional_count(payload, "thoughtsTokenCount")
        if reasoning is not None:
            output_tokens = None if output_tokens is None else output_tokens + reasoning
    try:
        return ModelUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cached_input_tokens=cached,
            reasoning_tokens=reasoning,
        )
    except ValidationError:
        raise ModelProtocolError("Invalid provider usage") from None


def _provider_error(
    payload: dict[str, JsonValue], request: ModelRequest
) -> ModelResponse | None:
    if "error" not in payload:
        return None
    error = _object(payload["error"], "Malformed provider error")
    raw_code = error.get("type", error.get("status", error.get("code")))
    error_code = str(raw_code) if type(raw_code) is int else raw_code
    if not isinstance(error_code, str) or not _ERROR_CODE.fullmatch(error_code):
        error_code = "provider_error"
    return _validated_response(
        ModelResponse(
            status="error",
            model=request.model,
            finish_reason="provider_error",
            error_code=error_code,
        ),
        request,
    )


def _validated_response(response: ModelResponse, request: ModelRequest) -> ModelResponse:
    try:
        return validate_response(response, request)
    except ModelProtocolError:
        raise
    except (TypeError, ValueError, ValidationError):
        raise ModelProtocolError("Malformed provider response") from None


def _make_tool_call(
    *,
    call_id: object,
    name: object,
    arguments: object,
    provider_state: dict[str, str] | None = None,
) -> ToolCall:
    if not isinstance(call_id, str) or not isinstance(name, str):
        raise ModelProtocolError("Malformed provider tool call")
    args = _object(arguments, "Malformed provider tool call")
    try:
        return ToolCall(
            call_id=call_id,
            name=name,
            arguments=args,
            provider_state=provider_state or {},
        )
    except (TypeError, ValueError, ValidationError):
        raise ModelProtocolError("Malformed provider tool call") from None


def _tool_result(message: ChatMessage) -> dict[str, JsonValue]:
    return parse_json_object(message.content)


class AnthropicCodec:
    """Codec for Anthropic's native Messages API."""

    _HEADERS: ClassVar[dict[str, str]] = {"anthropic-version": "2023-06-01"}

    @property
    def headers(self) -> dict[str, str]:
        return dict(self._HEADERS)

    def path(self, request: ModelRequest) -> str:
        del request
        return "/v1/messages"

    def encode(self, request: ModelRequest) -> dict[str, JsonValue]:  # noqa: C901
        messages: list[JsonValue] = []
        pending_results: list[JsonValue] = []

        def flush_results() -> None:
            if pending_results:
                messages.append({"role": "user", "content": list(pending_results)})
                pending_results.clear()

        for message in request.messages:
            if message.role == "tool":
                pending_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": cast("str", message.tool_call_id),
                        "content": message.content,
                    }
                )
                continue
            flush_results()
            if message.role == "user":
                messages.append({"role": "user", "content": message.content})
                continue
            content: list[JsonValue] = []
            if message.content:
                content.append({"type": "text", "text": message.content})
            if any(call.provider_state for call in message.tool_calls):
                raise ModelProtocolError(
                    "Anthropic tool calls cannot carry provider state"
                )
            content.extend(
                {
                    "type": "tool_use",
                    "id": call.call_id,
                    "name": call.name,
                    "input": call.arguments,
                }
                for call in message.tool_calls
            )
            messages.append({"role": "assistant", "content": content})
        flush_results()

        body: dict[str, JsonValue] = {
            "model": request.model,
            "max_tokens": request.max_output_tokens,
            "messages": messages,
        }
        if request.system:
            body["system"] = request.system
        if request.tools:
            body["tools"] = [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.parameters,
                }
                for tool in request.tools
            ]
        if request.output_schema is not None:
            body["output_config"] = {
                "format": {
                    "type": "json_schema",
                    "schema": request.output_schema,
                }
            }
        bounded_json(body)
        return body

    def decode(  # noqa: C901, PLR0912
        self, payload: dict[str, JsonValue], request: ModelRequest
    ) -> ModelResponse:
        bounded_json(payload)
        error = _provider_error(payload, request)
        if error is not None:
            return error

        stop_reason = _string(payload.get("stop_reason"))
        model = _string(payload.get("model"))
        content = _array(payload.get("content"))
        usage_payload = payload.get("usage", {})
        usage = _usage(
            _object(usage_payload),
            input_key="input_tokens",
            output_key="output_tokens",
            provider="anthropic",
        )

        text: list[str] = []
        calls: list[ToolCall] = []
        for raw_block in content:
            block = _object(raw_block)
            block_type = block.get("type")
            if block_type == "text":
                text.append(_string(block.get("text")))
            elif block_type == "tool_use":
                calls.append(
                    _make_tool_call(
                        call_id=block.get("id"),
                        name=block.get("name"),
                        arguments=block.get("input"),
                    )
                )
            else:
                raise ModelProtocolError("Unsupported Anthropic content block")
        if len(calls) > _MAX_TOOL_CALLS:
            raise ModelProtocolError("Too many Anthropic tool calls")

        if stop_reason == "refusal":
            status = "refused"
            output = None
            calls = []
        elif stop_reason in {
            "max_tokens",
            "model_context_window_exceeded",
            "pause_turn",
            "stop_sequence",
        }:
            status = "incomplete"
            output = None
            calls = []
        elif calls:
            if stop_reason != "tool_use":
                raise ModelProtocolError("Inconsistent Anthropic tool response")
            status = "tool_calls"
            output = None
        elif stop_reason == "end_turn":
            if not text:
                raise ModelProtocolError("Missing Anthropic structured output")
            status = "ok"
            output = parse_json_object("".join(text))
        elif stop_reason == "tool_use":
            raise ModelProtocolError("Missing Anthropic tool call")
        else:
            raise ModelProtocolError("Unsupported Anthropic stop reason")

        try:
            response = ModelResponse(
                status=status,
                model=model,
                output=output,
                tool_calls=tuple(calls),
                usage=usage,
                finish_reason=stop_reason,
            )
        except ValidationError:
            raise ModelProtocolError("Malformed Anthropic response") from None
        return _validated_response(response, request)


class GeminiCodec:
    """Codec for Google's native Gemini generateContent API."""

    @property
    def headers(self) -> dict[str, str]:
        return {}

    def path(self, request: ModelRequest) -> str:
        model = request.model
        if model.startswith("models/"):
            model = model.removeprefix("models/")
        if not _GEMINI_MODEL.fullmatch(model):
            raise ModelProtocolError("Invalid Gemini model identifier")
        return f"/v1beta/models/{quote(model, safe='')}:generateContent"

    def encode(self, request: ModelRequest) -> dict[str, JsonValue]:  # noqa: C901
        contents: list[JsonValue] = []
        pending_results: list[JsonValue] = []

        def flush_results() -> None:
            if pending_results:
                contents.append({"role": "user", "parts": list(pending_results)})
                pending_results.clear()

        for message in request.messages:
            if message.role == "tool":
                pending_results.append(
                    {
                        "functionResponse": {
                            "id": cast("str", message.tool_call_id),
                            "name": cast("str", message.tool_name),
                            "response": _tool_result(message),
                        }
                    }
                )
                continue
            flush_results()
            if message.role == "user":
                contents.append(
                    {"role": "user", "parts": [{"text": message.content}]}
                )
                continue
            parts: list[JsonValue] = []
            if message.content:
                parts.append({"text": message.content})
            for call in message.tool_calls:
                part: dict[str, JsonValue] = {
                    "functionCall": {
                        "id": call.call_id,
                        "name": call.name,
                        "args": call.arguments,
                    }
                }
                signature = call.provider_state.get("thought_signature")
                if signature:
                    part["thoughtSignature"] = signature
                parts.append(part)
            contents.append({"role": "model", "parts": parts})
        flush_results()

        generation_config: dict[str, JsonValue] = {
            "maxOutputTokens": request.max_output_tokens
        }
        if request.output_schema is not None:
            generation_config.update(
                {
                    "responseMimeType": "application/json",
                    "responseJsonSchema": request.output_schema,
                }
            )
        body: dict[str, JsonValue] = {
            "contents": contents,
            "generationConfig": generation_config,
        }
        if request.system:
            body["systemInstruction"] = {"parts": [{"text": request.system}]}
        if request.tools:
            body["tools"] = [
                {
                    "functionDeclarations": [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "parametersJsonSchema": tool.parameters,
                        }
                        for tool in request.tools
                    ]
                }
            ]
        bounded_json(body)
        return body

    def decode(  # noqa: C901, PLR0912, PLR0915
        self, payload: dict[str, JsonValue], request: ModelRequest
    ) -> ModelResponse:
        bounded_json(payload)
        error = _provider_error(payload, request)
        if error is not None:
            return error

        usage = _usage(
            _object(payload.get("usageMetadata", {})),
            input_key="promptTokenCount",
            output_key="candidatesTokenCount",
            total_key="totalTokenCount",
            provider="gemini",
        )
        candidates = _array(payload.get("candidates", []))
        if not candidates:
            feedback = _object(payload.get("promptFeedback", {}))
            block_reason = feedback.get("blockReason")
            if isinstance(block_reason, str) and block_reason != "BLOCK_REASON_UNSPECIFIED":
                return _validated_response(
                    ModelResponse(
                        status="refused",
                        model=self._response_model(payload, request),
                        usage=usage,
                        finish_reason=block_reason,
                    ),
                    request,
                )
            raise ModelProtocolError("Missing Gemini candidate")
        if len(candidates) != 1:
            raise ModelProtocolError("Gemini returned multiple candidates")

        candidate = _object(candidates[0])
        finish_reason = _string(candidate.get("finishReason"))
        model = self._response_model(payload, request)
        if finish_reason in {
            "SAFETY",
            "BLOCKLIST",
            "PROHIBITED_CONTENT",
            "SPII",
            "RECITATION",
            "IMAGE_SAFETY",
            "IMAGE_PROHIBITED_CONTENT",
        }:
            return _validated_response(
                ModelResponse(
                    status="refused",
                    model=model,
                    usage=usage,
                    finish_reason=finish_reason,
                ),
                request,
            )
        if finish_reason in {"MAX_TOKENS", "NO_IMAGE"}:
            return _validated_response(
                ModelResponse(
                    status="incomplete",
                    model=model,
                    usage=usage,
                    finish_reason=finish_reason,
                ),
                request,
            )
        if finish_reason in {
            "MALFORMED_FUNCTION_CALL",
            "UNEXPECTED_TOOL_CALL",
            "OTHER",
            "LANGUAGE",
            "IMAGE_OTHER",
        }:
            return _validated_response(
                ModelResponse(
                    status="error",
                    model=model,
                    usage=usage,
                    finish_reason=finish_reason,
                    error_code=finish_reason.lower(),
                ),
                request,
            )
        if finish_reason != "STOP":
            raise ModelProtocolError("Unsupported Gemini finish reason")

        content = _object(candidate.get("content"))
        if content.get("role") not in {None, "model"}:
            raise ModelProtocolError("Invalid Gemini candidate role")
        parts = _array(content.get("parts"))
        output_text: list[str] = []
        calls: list[ToolCall] = []
        deferred_signature: str | None = None
        previous_call_count = sum(
            len(message.tool_calls) for message in request.messages
        )
        for index, raw_part in enumerate(parts):
            part = _object(raw_part)
            signature = self._signature(part.get("thoughtSignature"))
            if part.get("thought") is True:
                if set(part) - {"text", "thought", "thoughtSignature"}:
                    raise ModelProtocolError("Unsupported Gemini thought block")
                if "text" in part:
                    _ = _string(part["text"])
                if signature:
                    deferred_signature = signature
                continue
            if "functionCall" in part:
                if set(part) - {"functionCall", "thoughtSignature"}:
                    raise ModelProtocolError("Unsupported Gemini function block")
                function = _object(part["functionCall"], "Malformed Gemini tool call")
                call_id = function.get("id")
                if call_id is None:
                    call_id = self._synthetic_call_id(
                        function, index, previous_call_count
                    )
                state_signature = signature or (deferred_signature if not calls else None)
                state = (
                    {"thought_signature": state_signature} if state_signature else {}
                )
                calls.append(
                    _make_tool_call(
                        call_id=call_id,
                        name=function.get("name"),
                        arguments=function.get("args", {}),
                        provider_state=state,
                    )
                )
                deferred_signature = None
                continue
            if "text" in part:
                if set(part) - {"text", "thoughtSignature"}:
                    raise ModelProtocolError("Unsupported Gemini text block")
                output_text.append(_string(part["text"]))
                continue
            raise ModelProtocolError("Unsupported Gemini content part")

        if len(calls) > _MAX_TOOL_CALLS:
            raise ModelProtocolError("Too many Gemini tool calls")
        if calls:
            status = "tool_calls"
            output = None
        elif output_text:
            status = "ok"
            output = parse_json_object("".join(output_text))
        else:
            raise ModelProtocolError("Missing Gemini structured output")

        try:
            response = ModelResponse(
                status=status,
                model=model,
                output=output,
                tool_calls=tuple(calls),
                usage=usage,
                finish_reason=finish_reason,
            )
        except ValidationError:
            raise ModelProtocolError("Malformed Gemini response") from None
        return _validated_response(response, request)

    @staticmethod
    def _response_model(
        payload: dict[str, JsonValue], request: ModelRequest
    ) -> str:
        model = payload.get("modelVersion", request.model)
        if not isinstance(model, str) or not model or len(model) > 128:
            raise ModelProtocolError("Invalid Gemini model version")
        return model

    @staticmethod
    def _signature(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value.encode()) > 16384:
            raise ModelProtocolError("Invalid Gemini thought signature")
        return value

    @staticmethod
    def _synthetic_call_id(
        function: dict[str, JsonValue], index: int, previous_call_count: int
    ) -> str:
        bounded_json(function, 16384)
        canonical = json.dumps(
            function, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        identity = previous_call_count.to_bytes(2, "big") + index.to_bytes(2, "big")
        digest = hashlib.sha256(identity + canonical).hexdigest()[:24]
        return f"gemini_{digest}"
