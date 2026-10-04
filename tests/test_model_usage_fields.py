"""Fixture tests for cached-input and reasoning token accounting."""

from __future__ import annotations

from typing import Any

import pytest

from terminus.model_gateway.compatible import OpenAICompatibleCodec
from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelProtocolError,
    ModelRequest,
    ModelUsage,
)
from terminus.model_gateway.native import AnthropicCodec, GeminiCodec

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
    "additionalProperties": False,
}


def _request() -> ModelRequest:
    return ModelRequest(
        model="m",
        system="s",
        messages=(ChatMessage(role="user", content="x"),),
        output_schema=SCHEMA,
        max_output_tokens=256,
    )


def _openai(usage: Any, provider: Any = "openai") -> ModelUsage:
    payload: dict[str, Any] = {
        "model": "m",
        "choices": [
            {
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": '{"verdict":"ok"}'},
            }
        ],
    }
    if usage is not None:
        payload["usage"] = usage
    return OpenAICompatibleCodec(provider).decode(payload, _request()).usage


def _anthropic(usage: Any) -> ModelUsage:
    payload: dict[str, Any] = {
        "model": "claude-x",
        "content": [{"type": "text", "text": '{"verdict":"ok"}'}],
        "stop_reason": "end_turn",
    }
    if usage is not None:
        payload["usage"] = usage
    return AnthropicCodec().decode(payload, _request()).usage


def _gemini(usage: Any) -> ModelUsage:
    payload: dict[str, Any] = {
        "modelVersion": "g",
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {"role": "model", "parts": [{"text": '{"verdict":"ok"}'}]},
            }
        ],
    }
    if usage is not None:
        payload["usageMetadata"] = usage
    return GeminiCodec().decode(payload, _request()).usage


def test_model_usage_defaults_are_unknown_not_zero() -> None:
    usage = ModelUsage()
    assert usage.cached_input_tokens is None
    assert usage.reasoning_tokens is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"input_tokens": 5, "cached_input_tokens": 6},
        {"output_tokens": 5, "reasoning_tokens": 6},
        {"cached_input_tokens": -1},
        {"reasoning_tokens": -1},
    ],
)
def test_model_usage_rejects_inconsistent_values(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        ModelUsage(**kwargs)


def test_model_usage_subsets_allowed_when_total_unknown() -> None:
    assert ModelUsage(cached_input_tokens=9).input_tokens is None
    assert ModelUsage(reasoning_tokens=9).output_tokens is None


@pytest.mark.parametrize(
    "provider", ["openai", "openrouter", "openai_compatible", "local"]
)
def test_openai_family_fields_present(provider: str) -> None:
    usage = _openai(
        {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "prompt_tokens_details": {"cached_tokens": 64, "audio_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 30},
        },
        provider,
    )
    assert (usage.input_tokens, usage.cached_input_tokens) == (100, 64)
    assert (usage.output_tokens, usage.reasoning_tokens) == (50, 30)
    assert usage.total_tokens == 150


def test_openai_family_zero_reported_is_kept_and_absent_is_none() -> None:
    zero = _openai(
        {
            "prompt_tokens": 4,
            "completion_tokens": 2,
            "prompt_tokens_details": {"cached_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 0},
        }
    )
    assert zero.cached_input_tokens == 0
    assert zero.reasoning_tokens == 0
    for usage in (
        {"prompt_tokens": 4, "completion_tokens": 2},
        {"prompt_tokens": 4, "prompt_tokens_details": {}},
        {"completion_tokens_details": None},
    ):
        parsed = _openai(usage)
        assert parsed.cached_input_tokens is None
        assert parsed.reasoning_tokens is None
    assert _openai(None).cached_input_tokens is None


def test_deepseek_cache_hit_and_miss_fields() -> None:
    usage = _openai(
        {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
            "prompt_cache_hit_tokens": 80,
            "prompt_cache_miss_tokens": 20,
            "completion_tokens_details": {"reasoning_tokens": 12},
        },
        "deepseek",
    )
    assert (usage.input_tokens, usage.cached_input_tokens) == (100, 80)
    assert usage.reasoning_tokens == 12


def test_deepseek_input_derived_only_from_hit_plus_miss() -> None:
    usage = _openai(
        {
            "completion_tokens": 2,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 4,
        },
        "deepseek",
    )
    assert usage.input_tokens == 7
    assert usage.cached_input_tokens == 3
    only_hit = _openai({"prompt_cache_hit_tokens": 3}, "deepseek")
    assert only_hit.input_tokens is None
    assert only_hit.cached_input_tokens == 3


@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": "5"}},
        {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": True}},
        {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": -1}},
        {"prompt_tokens": 10, "prompt_tokens_details": 5},
        {"completion_tokens": 10, "completion_tokens_details": [1]},
        {
            "completion_tokens": 10,
            "completion_tokens_details": {"reasoning_tokens": 1.5},
        },
        {"prompt_cache_hit_tokens": "x"},
        # inconsistent
        {"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": 11}},
        {"completion_tokens": 5, "completion_tokens_details": {"reasoning_tokens": 6}},
        {
            "prompt_tokens": 10,
            "prompt_tokens_details": {"cached_tokens": 4},
            "prompt_cache_hit_tokens": 5,
        },
    ],
)
def test_openai_family_malformed_or_inconsistent_rejected(
    usage: dict[str, Any],
) -> None:
    with pytest.raises(ModelProtocolError):
        _openai(usage, "deepseek")


def test_anthropic_normalizes_cache_into_input() -> None:
    usage = _anthropic(
        {
            "input_tokens": 10,
            "cache_read_input_tokens": 200,
            "cache_creation_input_tokens": 30,
            "output_tokens": 7,
        }
    )
    assert usage.input_tokens == 240
    assert usage.cached_input_tokens == 200
    assert usage.output_tokens == 7
    assert usage.reasoning_tokens is None  # not separately reported
    assert usage.total_tokens is None


def test_anthropic_no_cache_fields_keeps_reported_input() -> None:
    for extra in (
        {},
        {"cache_read_input_tokens": None, "cache_creation_input_tokens": None},
    ):
        usage = _anthropic({"input_tokens": 11, "output_tokens": 7, **extra})
        assert usage.input_tokens == 11
        assert usage.cached_input_tokens is None


def test_anthropic_zero_cache_is_reported_zero() -> None:
    usage = _anthropic(
        {
            "input_tokens": 11,
            "output_tokens": 7,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
        }
    )
    assert usage.input_tokens == 11
    assert usage.cached_input_tokens == 0


def test_anthropic_partial_cache_fields_make_input_unknown() -> None:
    only_read = _anthropic(
        {"input_tokens": 11, "output_tokens": 7, "cache_read_input_tokens": 50}
    )
    assert only_read.input_tokens is None
    assert only_read.cached_input_tokens == 50
    only_creation = _anthropic(
        {"input_tokens": 11, "output_tokens": 7, "cache_creation_input_tokens": 50}
    )
    assert only_creation.input_tokens is None
    assert only_creation.cached_input_tokens is None
    no_input = _anthropic(
        {
            "output_tokens": 7,
            "cache_read_input_tokens": 1,
            "cache_creation_input_tokens": 2,
        }
    )
    assert no_input.input_tokens is None
    assert no_input.cached_input_tokens == 1


@pytest.mark.parametrize(
    "usage",
    [
        {
            "input_tokens": 1,
            "cache_read_input_tokens": "5",
            "cache_creation_input_tokens": 0,
        },
        {
            "input_tokens": 1,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": -2,
        },
        {
            "input_tokens": 1,
            "cache_read_input_tokens": True,
            "cache_creation_input_tokens": 0,
        },
        {
            "input_tokens": 1,
            "cache_read_input_tokens": 1.5,
            "cache_creation_input_tokens": 0,
        },
    ],
)
def test_anthropic_malformed_cache_fields_rejected(usage: dict[str, Any]) -> None:
    with pytest.raises(ModelProtocolError):
        _anthropic(usage)


def test_gemini_normalizes_thoughts_into_output() -> None:
    usage = _gemini(
        {
            "promptTokenCount": 13,
            "cachedContentTokenCount": 8,
            "candidatesTokenCount": 5,
            "thoughtsTokenCount": 20,
            "totalTokenCount": 38,
        }
    )
    assert (usage.input_tokens, usage.cached_input_tokens) == (13, 8)
    assert (usage.output_tokens, usage.reasoning_tokens) == (25, 20)
    assert usage.total_tokens == 38


def test_gemini_absent_fields_are_none() -> None:
    usage = _gemini({"promptTokenCount": 13, "candidatesTokenCount": 5})
    assert usage.cached_input_tokens is None
    assert usage.reasoning_tokens is None
    assert usage.output_tokens == 5
    assert usage.total_tokens is None
    empty = _gemini(None)
    assert empty.input_tokens is None
    assert empty.output_tokens is None


def test_gemini_thoughts_without_candidates_leave_output_unknown() -> None:
    usage = _gemini({"promptTokenCount": 3, "thoughtsTokenCount": 9})
    assert usage.output_tokens is None
    assert usage.reasoning_tokens == 9


@pytest.mark.parametrize(
    "usage",
    [
        {"cachedContentTokenCount": "1"},
        {"thoughtsTokenCount": -1},
        {"thoughtsTokenCount": True},
        {"cachedContentTokenCount": None},
        {"promptTokenCount": 2, "cachedContentTokenCount": 3},
    ],
)
def test_gemini_malformed_or_inconsistent_rejected(usage: dict[str, Any]) -> None:
    with pytest.raises(ModelProtocolError):
        _gemini(usage)
