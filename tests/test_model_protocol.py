"""Shared contract acceptance uses bounded synthetic provider fixtures."""

from __future__ import annotations

import asyncio

import httpx2
import pytest
from pydantic import ValidationError

from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ModelResponse,
    ModelUsage,
    ToolCall,
    ToolSpec,
    parse_json_object,
    validate_response,
)
from terminus.model_gateway.fixture_client import FixtureModelClient

SCHEMA = {
    "type": "object",
    "properties": {"finding": {"type": "string"}},
    "required": ["finding"],
    "additionalProperties": False,
}
PARAMS = {
    "type": "object",
    "properties": {"endpoint": {"type": "string"}},
    "required": ["endpoint"],
    "additionalProperties": False,
}


def request(**changes):
    return ModelRequest(
        model="fixture-model",
        messages=(ChatMessage(role="user", content="Fixture investigation"),),
        output_schema=SCHEMA,
        **changes,
    )


def completion(content='{"finding":"recorded fixture"}', **changes):
    return {
        "model": "fixture-model",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content},
            }
        ],
        **changes,
    }


@pytest.mark.parametrize(
    "content", ["[]", '{"a":1,"a":2}', '{"n":NaN}', "```json\n{}\n```", "not JSON"]
)
def test_non_structured_or_ambiguous_json_fails(content):
    with pytest.raises(ModelProtocolError):
        parse_json_object(content)


@pytest.mark.parametrize(
    "output", [{"finding": 1}, {"finding": "ok", "invented": True}, {}]
)
def test_schema_mismatch_cannot_publish_findings(output):
    result = ModelResponse(status="ok", model="fixture-model", output=output)
    with pytest.raises(ModelProtocolError):
        validate_response(result, request())


def test_unknown_tools_and_extra_arguments_fail():
    declared = ToolSpec(name="endpoint_context", parameters=PARAMS)
    call = ToolCall(call_id="call-1", name="arbitrary_shell", arguments={})
    with pytest.raises(ModelProtocolError):
        validate_response(
            ModelResponse(
                status="tool_calls", model="fixture-model", tool_calls=(call,)
            ),
            request(tools=(declared,)),
        )
    call = ToolCall(
        call_id="call-1",
        name=declared.name,
        arguments={"endpoint": "endpoint-1", "command": "shell"},
    )
    with pytest.raises(ModelProtocolError):
        validate_response(
            ModelResponse(
                status="tool_calls", model="fixture-model", tool_calls=(call,)
            ),
            request(tools=(declared,)),
        )


def test_tool_results_bind_to_pending_call_and_name():
    tool = ToolSpec(name="endpoint_context", parameters=PARAMS)
    call = ToolCall(
        call_id="call-1", name=tool.name, arguments={"endpoint": "endpoint-1"}
    )
    messages = (
        ChatMessage(role="user", content="Investigate"),
        ChatMessage(role="assistant", tool_calls=(call,)),
        ChatMessage(
            role="tool",
            content='{"status":"unavailable"}',
            tool_call_id="call-1",
            tool_name=tool.name,
        ),
    )
    value = ModelRequest(model="fixture", messages=messages, tools=(tool,))
    assert value.messages[-1].tool_call_id == call.call_id
    with pytest.raises(ValidationError):
        ModelRequest(
            model="fixture",
            tools=(tool,),
            messages=(
                *messages[:-1],
                messages[-1].model_copy(update={"tool_call_id": "foreign"}),
            ),
        )


@pytest.mark.parametrize(
    "schema",
    [
        {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": True,
        },
        {"$ref": "https://external/schema"},
        {"type": "string"},
    ],
)
def test_unsupported_schema_is_rejected_before_provider_call(schema):
    with pytest.raises(ValidationError):
        ModelRequest(
            model="fixture",
            messages=(ChatMessage(role="user", content="x"),),
            output_schema=schema,
        )


def test_missing_usage_stays_unknown_and_invalid_counts_fail():
    assert ModelUsage().input_tokens is None
    with pytest.raises(ValidationError):
        ModelUsage(input_tokens=True)
    with pytest.raises(ValidationError):
        ModelUsage(output_tokens=-1)


def test_network_transport_cannot_be_installed():
    with pytest.raises(ModelProtocolError):
        FixtureModelClient("openai", object())


@pytest.mark.asyncio
async def test_fixture_transport_auth_and_structured_result():
    seen = []

    def fixture(req):
        seen.append(req)
        return httpx2.Response(200, json=completion())

    result = await FixtureModelClient("openai", httpx2.MockTransport(fixture)).respond(
        request()
    )
    assert result.status == "ok"
    assert result.output == {"finding": "recorded fixture"}
    assert seen[0].headers["authorization"] == "Bearer fixture-key-not-a-credential"
    assert result.usage.input_tokens is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (401, "authentication_denied"),
        (429, "rate_limited"),
        (400, "unsupported_request"),
        (500, "provider_unavailable"),
        (302, "provider_unavailable"),
    ],
)
async def test_error_mapping_does_not_echo_body_or_retry(code, expected):
    calls = []

    def fixture(req):
        calls.append(req)
        return httpx2.Response(
            code,
            text="secret-raw-provider-error",
            headers={"location": "https://external.invalid"},
        )

    result = await FixtureModelClient("openai", httpx2.MockTransport(fixture)).respond(
        request()
    )
    assert result.error_code == expected
    assert result.output is None
    assert "secret-raw" not in result.model_dump_json()
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_timeout_and_cancellation_are_conservative():
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def fixture(req):
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    client = FixtureModelClient(
        "openai", httpx2.MockTransport(fixture), deadline_seconds=0.01
    )
    result = await client.respond(request())
    assert result.error_code == "timeout_unknown_usage"
    assert result.usage.total_tokens is None
    stopped.clear()
    pending = asyncio.create_task(client.respond(request()))
    await asyncio.sleep(0)
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_oversized_wire_and_output_never_publish():
    big = completion('{"finding":"' + "x" * 70000 + '"}')
    result = await FixtureModelClient(
        "openai", httpx2.MockTransport(lambda req: httpx2.Response(200, json=big))
    ).respond(request())
    assert result.status == "error"
    big = completion("x" * 1048576)
    result = await FixtureModelClient(
        "openai", httpx2.MockTransport(lambda req: httpx2.Response(200, json=big))
    ).respond(request())
    assert result.error_code == "response_too_large"


@pytest.mark.asyncio
async def test_copied_request_cannot_bypass_admission():
    calls = []
    client = FixtureModelClient(
        "openai",
        httpx2.MockTransport(
            lambda req: calls.append(req) or httpx2.Response(200, json=completion())
        ),
    )
    result = await client.respond(
        request().model_copy(update={"max_output_tokens": 999999})
    )
    assert result.status == "error"
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        "openai",
        "openrouter",
        "deepseek",
        "openai_compatible",
        "local",
        "anthropic",
        "gemini",
    ],
)
async def test_all_provider_families_have_fixture_paths_and_auth(provider):
    seen = []
    text = '{"finding":"fixture-native"}'
    if provider == "anthropic":
        payload = {
            "model": "fixture-model",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}],
        }
    elif provider == "gemini":
        payload = {
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"text": text}]},
                }
            ]
        }
    else:
        payload = completion(text)

    def fixture(req):
        seen.append(req)
        return httpx2.Response(200, json=payload)

    endpoint = {
        "openai_compatible": "https://compatible.invalid/v1",
        "local": "http://127.0.0.1:11434/v1",
    }.get(provider)
    client = FixtureModelClient(
        provider, httpx2.MockTransport(fixture), base_url=endpoint
    )
    result = await client.respond(request())
    assert result.status == "ok", result.error_code
    assert result.output == {"finding": "fixture-native"}
    assert len(seen) == 1
    if provider == "anthropic":
        assert seen[0].url.path == "/v1/messages"
        assert seen[0].headers["x-api-key"] == "fixture-key-not-a-credential"
    elif provider == "gemini":
        assert seen[0].url.path == "/v1beta/models/fixture-model:generateContent"
        assert seen[0].headers["x-goog-api-key"] == "fixture-key-not-a-credential"
    else:
        assert seen[0].url.path.endswith("/chat/completions")


@pytest.mark.asyncio
async def test_duplicate_outer_provider_fields_are_invalid():
    wire = '{"choices":[],"choices":[]}'
    client = FixtureModelClient(
        "openai", httpx2.MockTransport(lambda req: httpx2.Response(200, text=wire))
    )
    result = await client.respond(request())
    assert result.status == "error"
    assert result.output is None
