"""Synthetic fixture tests for provider-native codecs; no provider I/O."""

from __future__ import annotations

import pytest

from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ToolCall,
    ToolSpec,
)
from terminus.model_gateway.native import AnthropicCodec, GeminiCodec

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
    "additionalProperties": False,
}
TOOL_SCHEMA = {
    "type": "object",
    "properties": {"host": {"type": "string"}},
    "required": ["host"],
    "additionalProperties": False,
}


def _request(
    *,
    model: str = "native-model",
    messages: tuple[ChatMessage, ...] | None = None,
    output_schema: dict[str, object] | None = OUTPUT_SCHEMA,
    tools: tuple[ToolSpec, ...] = (),
) -> ModelRequest:
    return ModelRequest(
        model=model,
        system="Return the bounded incident result.",
        messages=messages or (ChatMessage(role="user", content="Synthetic alert"),),
        output_schema=output_schema,
        tools=tools,
        max_output_tokens=4096,
    )


def _tool() -> ToolSpec:
    return ToolSpec(
        name="lookup_host",
        description="Look up a synthetic fixture host.",
        parameters=TOOL_SCHEMA,
    )


def _tool_continuation(*, signature: str | None = None) -> ModelRequest:
    state = {"thought_signature": signature} if signature else {}
    call = ToolCall(
        call_id="call_fixture_1",
        name="lookup_host",
        arguments={"host": "fixture-01"},
        provider_state=state,
    )
    return _request(
        messages=(
            ChatMessage(role="user", content="Check the fixture host"),
            ChatMessage(role="assistant", tool_calls=(call,)),
            ChatMessage(
                role="tool",
                content='{"risk":"low"}',
                tool_call_id=call.call_id,
                tool_name=call.name,
            ),
        ),
        tools=(_tool(),),
    )


def test_anthropic_encodes_native_structured_output_and_tools() -> None:
    codec = AnthropicCodec()
    request = _request(tools=(_tool(),))

    assert codec.path(request) == "/v1/messages"
    assert codec.headers == {"anthropic-version": "2023-06-01"}
    assert codec.encode(request) == {
        "model": "native-model",
        "max_tokens": 4096,
        "system": "Return the bounded incident result.",
        "messages": [{"role": "user", "content": "Synthetic alert"}],
        "tools": [
            {
                "name": "lookup_host",
                "description": "Look up a synthetic fixture host.",
                "input_schema": TOOL_SCHEMA,
            }
        ],
        "output_config": {
            "format": {"type": "json_schema", "schema": OUTPUT_SCHEMA}
        },
    }


def test_anthropic_encodes_native_tool_continuation() -> None:
    body = AnthropicCodec().encode(_tool_continuation())

    assert body["messages"] == [
        {"role": "user", "content": "Check the fixture host"},
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "call_fixture_1",
                    "name": "lookup_host",
                    "input": {"host": "fixture-01"},
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "call_fixture_1",
                    "content": '{"risk":"low"}',
                }
            ],
        },
    ]


def test_anthropic_rejects_gemini_provider_state() -> None:
    with pytest.raises(ModelProtocolError, match="provider state"):
        AnthropicCodec().encode(
            _tool_continuation(signature="gemini-only-opaque-state")
        )


def test_anthropic_decodes_structured_output_and_actual_usage() -> None:
    response = AnthropicCodec().decode(
        {
            "type": "message",
            "role": "assistant",
            "model": "claude-fixture",
            "content": [{"type": "text", "text": '{"verdict":"safe"}'}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        },
        _request(),
    )

    assert response.status == "ok"
    assert response.output == {"verdict": "safe"}
    assert response.usage.input_tokens == 11
    assert response.usage.output_tokens == 7
    assert response.usage.total_tokens is None


def test_anthropic_decodes_native_tool_call() -> None:
    request = _request(output_schema=None, tools=(_tool(),))
    response = AnthropicCodec().decode(
        {
            "model": "claude-fixture",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_fixture_1",
                    "name": "lookup_host",
                    "input": {"host": "fixture-01"},
                }
            ],
            "stop_reason": "tool_use",
        },
        request,
    )

    assert response.status == "tool_calls"
    assert response.tool_calls == (
        ToolCall(
            call_id="toolu_fixture_1",
            name="lookup_host",
            arguments={"host": "fixture-01"},
        ),
    )
    assert response.usage.input_tokens is None
    assert response.usage.total_tokens is None


def test_anthropic_discards_text_preface_when_returning_tool_calls() -> None:
    response = AnthropicCodec().decode(
        {
            "model": "claude-fixture",
            "content": [
                {"type": "text", "text": "I will inspect the synthetic host."},
                {
                    "type": "tool_use",
                    "id": "toolu_fixture_1",
                    "name": "lookup_host",
                    "input": {"host": "fixture-01"},
                },
            ],
            "stop_reason": "tool_use",
        },
        _request(output_schema=None, tools=(_tool(),)),
    )

    assert response.status == "tool_calls"
    assert response.output is None
    assert "I will inspect" not in response.model_dump_json()


@pytest.mark.parametrize(
    ("reason", "status"),
    [("refusal", "refused"), ("max_tokens", "incomplete"), ("pause_turn", "incomplete")],
)
def test_anthropic_maps_nonpublishable_stops(reason: str, status: str) -> None:
    response = AnthropicCodec().decode(
        {
            "model": "claude-fixture",
            "content": [{"type": "text", "text": "partial provider text"}],
            "stop_reason": reason,
        },
        _request(),
    )

    assert response.status == status
    assert response.output is None


@pytest.mark.parametrize(
    "payload",
    [
        {
            "model": "claude-fixture",
            "content": [{"type": "text", "text": "```json\n{}\n```"}],
            "stop_reason": "end_turn",
        },
        {
            "model": "claude-fixture",
            "content": [{"type": "image", "source": {}}],
            "stop_reason": "end_turn",
        },
        {
            "model": "claude-fixture",
            "content": [{"type": "text", "text": '{"verdict":"safe"}'}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": True},
        },
    ],
)
def test_anthropic_rejects_ambiguous_or_malformed_fixtures(payload: dict) -> None:
    with pytest.raises(ModelProtocolError):
        AnthropicCodec().decode(payload, _request(tools=(_tool(),)))


def test_gemini_encodes_native_structured_output_and_safe_path() -> None:
    codec = GeminiCodec()
    request = _request(model="models/gemini-2.5-flash", tools=(_tool(),))
    body = codec.encode(request)

    assert codec.path(request) == "/v1beta/models/gemini-2.5-flash:generateContent"
    assert codec.headers == {}
    assert body == {
        "systemInstruction": {
            "parts": [{"text": "Return the bounded incident result."}]
        },
        "contents": [
            {"role": "user", "parts": [{"text": "Synthetic alert"}]}
        ],
        "generationConfig": {
            "maxOutputTokens": 4096,
            "responseMimeType": "application/json",
            "responseJsonSchema": OUTPUT_SCHEMA,
        },
        "tools": [
            {
                "functionDeclarations": [
                    {
                        "name": "lookup_host",
                        "description": "Look up a synthetic fixture host.",
                        "parametersJsonSchema": TOOL_SCHEMA,
                    }
                ]
            }
        ],
    }


def test_gemini_rejects_model_namespace_injection() -> None:
    request = _request(model="publisher/model")
    with pytest.raises(ModelProtocolError, match="model identifier"):
        GeminiCodec().path(request)


def test_gemini_echoes_call_id_and_opaque_signature_in_continuation() -> None:
    body = GeminiCodec().encode(_tool_continuation(signature="opaque-fixture-signature"))

    assert body["contents"] == [
        {"role": "user", "parts": [{"text": "Check the fixture host"}]},
        {
            "role": "model",
            "parts": [
                {
                    "functionCall": {
                        "id": "call_fixture_1",
                        "name": "lookup_host",
                        "args": {"host": "fixture-01"},
                    },
                    "thoughtSignature": "opaque-fixture-signature",
                }
            ],
        },
        {
            "role": "user",
            "parts": [
                {
                    "functionResponse": {
                        "id": "call_fixture_1",
                        "name": "lookup_host",
                        "response": {"risk": "low"},
                    }
                }
            ],
        },
    ]


def test_gemini_decodes_structured_output_and_actual_usage() -> None:
    response = GeminiCodec().decode(
        {
            "modelVersion": "gemini-fixture",
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [{"text": '{"verdict":"safe"}'}],
                    },
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 13,
                "candidatesTokenCount": 5,
                "totalTokenCount": 21,
            },
        },
        _request(),
    )

    assert response.status == "ok"
    assert response.output == {"verdict": "safe"}
    assert response.usage.model_dump() == {
        "input_tokens": 13,
        "output_tokens": 5,
        "total_tokens": 21,
    }


def test_gemini_preserves_signature_without_returning_thought_text() -> None:
    request = _request(output_schema=None, tools=(_tool(),))
    fixture = {
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {
                    "role": "model",
                    "parts": [
                        {
                            "text": "private synthetic thought",
                            "thought": True,
                            "thoughtSignature": "opaque-signature",
                        },
                        {
                            "functionCall": {
                                "name": "lookup_host",
                                "args": {"host": "fixture-01"},
                            }
                        },
                    ],
                },
            }
        ]
    }

    first = GeminiCodec().decode(fixture, request)
    second = GeminiCodec().decode(fixture, request)

    assert first.status == "tool_calls"
    assert first.output is None
    assert first.tool_calls[0].call_id.startswith("gemini_")
    assert first.tool_calls[0].call_id == second.tool_calls[0].call_id
    assert first.tool_calls[0].provider_state == {
        "thought_signature": "opaque-signature"
    }
    assert "private synthetic thought" not in first.model_dump_json()


def test_gemini_synthetic_call_ids_advance_across_tool_rounds() -> None:
    fixture = {
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {
                    "parts": [
                        {
                            "functionCall": {
                                "name": "lookup_host",
                                "args": {"host": "fixture-01"},
                            }
                        }
                    ]
                },
            }
        ]
    }
    first = GeminiCodec().decode(
        fixture, _request(output_schema=None, tools=(_tool(),))
    )
    continued = GeminiCodec().decode(fixture, _tool_continuation())

    assert first.tool_calls[0].call_id != continued.tool_calls[0].call_id


def test_gemini_preserves_provider_function_call_id() -> None:
    response = GeminiCodec().decode(
        {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "id": "provider_call_7",
                                    "name": "lookup_host",
                                    "args": {"host": "fixture-01"},
                                },
                                "thoughtSignature": "opaque",
                            }
                        ]
                    },
                }
            ]
        },
        _request(output_schema=None, tools=(_tool(),)),
    )

    assert response.tool_calls[0].call_id == "provider_call_7"
    assert response.tool_calls[0].provider_state["thought_signature"] == "opaque"


def test_gemini_discards_text_preface_when_returning_tool_calls() -> None:
    response = GeminiCodec().decode(
        {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "parts": [
                            {"text": "I will inspect the synthetic host."},
                            {
                                "functionCall": {
                                    "name": "lookup_host",
                                    "args": {"host": "fixture-01"},
                                }
                            },
                        ]
                    },
                }
            ]
        },
        _request(output_schema=None, tools=(_tool(),)),
    )

    assert response.status == "tool_calls"
    assert response.output is None
    assert "I will inspect" not in response.model_dump_json()


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ({"promptFeedback": {"blockReason": "SAFETY"}}, "refused"),
        (
            {
                "candidates": [
                    {"finishReason": "SAFETY", "content": {"parts": []}}
                ]
            },
            "refused",
        ),
        (
            {
                "candidates": [
                    {
                        "finishReason": "MAX_TOKENS",
                        "content": {"parts": [{"text": "partial"}]},
                    }
                ]
            },
            "incomplete",
        ),
    ],
)
def test_gemini_maps_refusal_and_truncation(payload: dict, status: str) -> None:
    response = GeminiCodec().decode(payload, _request())
    assert response.status == status
    assert response.output is None


@pytest.mark.parametrize(
    "payload",
    [
        {
            "candidates": [
                {"finishReason": "STOP", "content": {"parts": [{"text": "{}"}]}},
                {"finishReason": "STOP", "content": {"parts": [{"text": "{}"}]}},
            ]
        },
        {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"parts": [{"inlineData": {"data": "abc"}}]},
                }
            ]
        },
        {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"parts": [{"text": '{"verdict":"safe"}'}]},
                }
            ],
            "usageMetadata": {"totalTokenCount": False},
        },
    ],
)
def test_gemini_rejects_ambiguous_or_malformed_fixtures(payload: dict) -> None:
    with pytest.raises(ModelProtocolError):
        GeminiCodec().decode(payload, _request(tools=(_tool(),)))


@pytest.mark.parametrize("codec", [AnthropicCodec(), GeminiCodec()])
def test_native_provider_error_is_bounded_and_does_not_expose_message(codec) -> None:
    response = codec.decode(
        {
            "error": {
                "type": "rate_limit_error",
                "message": "sensitive raw provider detail",
            }
        },
        _request(),
    )

    assert response.status == "error"
    assert response.error_code == "rate_limit_error"
    assert "sensitive raw provider detail" not in response.model_dump_json()


def test_native_output_is_validated_against_requested_schema() -> None:
    with pytest.raises(ModelProtocolError, match="schema"):
        AnthropicCodec().decode(
            {
                "model": "claude-fixture",
                "content": [{"type": "text", "text": '{"wrong":"field"}'}],
                "stop_reason": "end_turn",
            },
            _request(),
        )
