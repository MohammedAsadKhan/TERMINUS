"""Synthetic fixture tests for the OpenAI-compatible provider codec."""

from __future__ import annotations

from typing import cast

import pytest
from pydantic import JsonValue

from terminus.model_gateway.compatible import CompatibleProvider, OpenAICompatibleCodec
from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ToolCall,
    ToolSpec,
)


OUTPUT_SCHEMA: dict[str, JsonValue] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "score": {"type": "integer"},
    },
    "required": ["summary", "score"],
    "additionalProperties": False,
}
TOOL_SCHEMA: dict[str, JsonValue] = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


def _request(
    *,
    output_schema: dict[str, JsonValue] | None = OUTPUT_SCHEMA,
    tools: tuple[ToolSpec, ...] = (),
    messages: tuple[ChatMessage, ...] | None = None,
) -> ModelRequest:
    if messages is None:
        messages = (ChatMessage(role="user", content="fixture event"),)
    return ModelRequest(
        model="vendor/model-latest",
        system="Analyze the event.",
        messages=messages,
        output_schema=output_schema,
        tools=tools,
        max_output_tokens=700,
    )


def _completion(
    *,
    content: str | None = '{"summary":"safe","score":7}',
    finish_reason: str = "stop",
    model: str | None = "vendor/model-2026-10-01",
    usage: JsonValue = None,
    tool_calls: JsonValue = None,
    refusal: JsonValue = None,
) -> dict[str, JsonValue]:
    message: dict[str, JsonValue] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    if refusal is not None:
        message["refusal"] = refusal
    payload: dict[str, JsonValue] = {
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
    }
    if model is not None:
        payload["model"] = model
    if usage is not None:
        payload["usage"] = usage
    return payload


def test_encode_openai_strict_schema_and_modern_token_parameter() -> None:
    codec = OpenAICompatibleCodec("openai")

    payload = codec.encode(_request())

    assert codec.path(_request()) == "/chat/completions"
    assert codec.headers == {}
    assert payload == {
        "model": "vendor/model-latest",
        "messages": [
            {"role": "system", "content": "Analyze the event."},
            {"role": "user", "content": "fixture event"},
        ],
        "max_completion_tokens": 700,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "terminus_output",
                "strict": True,
                "schema": OUTPUT_SCHEMA,
            },
        },
    }


@pytest.mark.parametrize("provider", ["openrouter", "openai_compatible", "local"])
def test_other_compatible_providers_keep_strict_schema(
    provider: CompatibleProvider,
) -> None:
    payload = OpenAICompatibleCodec(provider).encode(_request())
    assert payload["max_tokens"] == 700
    assert payload["response_format"] == {
        "type": "json_schema",
        "json_schema": {
            "name": "terminus_output",
            "strict": True,
            "schema": OUTPUT_SCHEMA,
        },
    }


def test_deepseek_uses_documented_json_mode_with_explicit_schema_instruction() -> None:
    payload = OpenAICompatibleCodec("deepseek").encode(_request())

    assert payload["max_tokens"] == 700
    assert payload["response_format"] == {"type": "json_object"}
    messages = cast("list[dict[str, JsonValue]]", payload["messages"])
    assert messages[0]["role"] == "system"
    content = cast("str", messages[0]["content"])
    assert content.startswith("Analyze the event.\n\nReturn only")
    assert '"additionalProperties":false' in content


def test_encode_tools_and_continuation_preserves_call_id() -> None:
    tool = ToolSpec(name="lookup_host", description="Look up a host", parameters=TOOL_SCHEMA)
    call = ToolCall(call_id="call_1", name="lookup_host", arguments={"host": "web-1"})
    request = _request(
        output_schema=None,
        tools=(tool,),
        messages=(
            ChatMessage(role="user", content="Inspect web-1"),
            ChatMessage(role="assistant", tool_calls=(call,)),
            ChatMessage(
                role="tool",
                content='{"status":"clean"}',
                tool_call_id="call_1",
                tool_name="lookup_host",
            ),
        ),
    )

    payload = OpenAICompatibleCodec().encode(request)

    assert payload["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "lookup_host",
                "description": "Look up a host",
                "parameters": TOOL_SCHEMA,
            },
        }
    ]
    messages = cast("list[dict[str, JsonValue]]", payload["messages"])
    encoded_calls = cast("list[JsonValue]", messages[2]["tool_calls"])
    assert encoded_calls[0] == {
        "id": "call_1",
        "type": "function",
        "function": {
            "name": "lookup_host",
            "arguments": '{"host":"web-1"}',
        },
    }
    assert messages[3] == {
        "role": "tool",
        "content": '{"status":"clean"}',
        "tool_call_id": "call_1",
    }


def test_encode_rejects_native_provider_state() -> None:
    tool = ToolSpec(name="lookup_host", parameters=TOOL_SCHEMA)
    call = ToolCall(
        call_id="call_1",
        name="lookup_host",
        arguments={"host": "web-1"},
        provider_state={"thought_signature": "opaque"},
    )
    request = _request(
        output_schema=None,
        tools=(tool,),
        messages=(
            ChatMessage(role="user", content="Inspect"),
            ChatMessage(role="assistant", tool_calls=(call,)),
            ChatMessage(
                role="tool",
                content='{"status":"clean"}',
                tool_call_id="call_1",
                tool_name="lookup_host",
            ),
        ),
    )

    with pytest.raises(ModelProtocolError, match="provider state"):
        _ = OpenAICompatibleCodec().encode(request)


def test_decode_structured_output_model_and_native_usage() -> None:
    response = OpenAICompatibleCodec().decode(
        _completion(
            usage={"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
        ),
        _request(),
    )

    assert response.status == "ok"
    assert response.model == "vendor/model-2026-10-01"
    assert response.output == {"summary": "safe", "score": 7}
    assert response.finish_reason == "stop"
    assert response.usage.input_tokens == 12
    assert response.usage.output_tokens == 5
    assert response.usage.total_tokens == 17


def test_decode_missing_model_and_usage_does_not_invent_values() -> None:
    response = OpenAICompatibleCodec().decode(
        _completion(model=None),
        _request(),
    )

    assert response.model == "vendor/model-latest"
    assert response.usage.input_tokens is None
    assert response.usage.output_tokens is None
    assert response.usage.total_tokens is None


def test_decode_refusal_and_content_filter_are_non_success() -> None:
    codec = OpenAICompatibleCodec()
    refusal = codec.decode(
        _completion(content=None, refusal="I cannot assist."),
        _request(),
    )
    filtered = codec.decode(
        _completion(content=None, finish_reason="content_filter"),
        _request(),
    )

    assert refusal.status == "refused"
    assert refusal.output is None
    assert filtered.status == "refused"


def test_decode_length_never_publishes_even_valid_json() -> None:
    response = OpenAICompatibleCodec().decode(
        _completion(finish_reason="length"),
        _request(),
    )

    assert response.status == "incomplete"
    assert response.output is None


def test_decode_valid_tool_calls_and_apply_shared_schema_gate() -> None:
    request = _request(
        output_schema=None,
        tools=(ToolSpec(name="lookup_host", parameters=TOOL_SCHEMA),),
    )
    response = OpenAICompatibleCodec().decode(
        _completion(
            content=None,
            finish_reason="tool_calls",
            tool_calls=[
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "lookup_host",
                        "arguments": '{"host":"web-1"}',
                    },
                }
            ],
        ),
        request,
    )

    assert response.status == "tool_calls"
    assert response.tool_calls == (
        ToolCall(
            call_id="call_1",
            name="lookup_host",
            arguments={"host": "web-1"},
        ),
    )


@pytest.mark.parametrize(
    "tool_calls",
    [
        [
            {
                "id": "call_1",
                "type": "function",
                "function": {"name": "missing", "arguments": "{}"},
            }
        ],
        [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "lookup_host",
                    "arguments": '{"host":"web-1","extra":true}',
                },
            }
        ],
    ],
)
def test_decode_shared_gate_rejects_unknown_tools_and_excess_arguments(
    tool_calls: list[JsonValue],
) -> None:
    request = _request(
        output_schema=None,
        tools=(ToolSpec(name="lookup_host", parameters=TOOL_SCHEMA),),
    )

    with pytest.raises(ModelProtocolError):
        _ = OpenAICompatibleCodec().decode(
            _completion(
                content=None,
                finish_reason="tool_calls",
                tool_calls=tool_calls,
            ),
            request,
        )


@pytest.mark.parametrize(
    "arguments",
    ["not json", "[]", '{"host":NaN}', '{"host":"a","host":"b"}'],
)
def test_decode_rejects_malformed_tool_arguments(arguments: str) -> None:
    request = _request(
        output_schema=None,
        tools=(ToolSpec(name="lookup_host", parameters=TOOL_SCHEMA),),
    )
    calls: list[JsonValue] = [
        {
            "id": "call_1",
            "type": "function",
            "function": {"name": "lookup_host", "arguments": arguments},
        }
    ]

    with pytest.raises(ModelProtocolError):
        _ = OpenAICompatibleCodec().decode(
            _completion(
                content=None,
                finish_reason="tool_calls",
                tool_calls=calls,
            ),
            request,
        )


@pytest.mark.parametrize(
    "content",
    [
        "not json",
        "```json\n{}\n```",
        "[]",
        '{"summary":"safe","score":NaN}',
        '{"summary":"safe","summary":"duplicate","score":7}',
    ],
)
def test_decode_rejects_non_object_or_malformed_structured_text(content: str) -> None:
    with pytest.raises(ModelProtocolError):
        _ = OpenAICompatibleCodec().decode(_completion(content=content), _request())


def test_decode_shared_gate_rejects_schema_mismatch() -> None:
    with pytest.raises(ModelProtocolError, match="schema"):
        _ = OpenAICompatibleCodec().decode(
            _completion(content='{"summary":"safe","score":"high"}'),
            _request(),
        )


MALFORMED_RESPONSES: tuple[dict[str, JsonValue], ...] = (
    {"choices": []},
    {"choices": [{}, {}]},
    {"choices": ["bad"]},
    {
        "choices": [
            {"finish_reason": "stop", "message": {"role": "user", "content": "{}"}}
        ]
    },
    _completion(finish_reason="function_call"),
    _completion(finish_reason="unexpected"),
    _completion(finish_reason="unexpected", refusal="declined"),
    _completion(finish_reason="tool_calls", tool_calls=[]),
    _completion(finish_reason="stop", tool_calls=[{}]),
    {"error": {"message": "do not expose fixture body"}},
)


@pytest.mark.parametrize("payload", MALFORMED_RESPONSES)
def test_decode_rejects_ambiguous_or_malformed_response(
    payload: dict[str, JsonValue],
) -> None:
    with pytest.raises(ModelProtocolError) as caught:
        _ = OpenAICompatibleCodec().decode(payload, _request())
    assert "do not expose fixture body" not in str(caught.value)


@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": True},
        {"completion_tokens": -1},
        {"total_tokens": 1.5},
        {"prompt_tokens": 1_000_000_001},
        "bad",
    ],
)
def test_decode_rejects_invalid_usage(usage: JsonValue) -> None:
    with pytest.raises(ModelProtocolError):
        _ = OpenAICompatibleCodec().decode(_completion(usage=usage), _request())
