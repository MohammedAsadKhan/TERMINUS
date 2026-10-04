"""Fixture-only transport harness; no production credential or network wiring."""

from __future__ import annotations

import asyncio
from typing import ClassVar, Protocol

import httpx2
from pydantic import JsonValue

from terminus.model_gateway.contracts import (
    ModelProtocolError,
    ModelRequest,
    ModelResponse,
    bounded_json,
    parse_json_object,
    validate_response,
)
from terminus.model_gateway.models import Provider, normalize_base_url


class ModelCodec(Protocol):
    @property
    def headers(self) -> dict[str, str]: ...

    def path(self, request: ModelRequest) -> str: ...

    def encode(self, request: ModelRequest) -> dict[str, JsonValue]: ...

    def decode(
        self, payload: dict[str, JsonValue], request: ModelRequest
    ) -> ModelResponse: ...


class FixtureModelClient:
    """Exercise real codecs with an explicitly supplied MockTransport only."""

    fixture_only: ClassVar[bool] = True

    def __init__(
        self,
        provider: Provider,
        transport: httpx2.MockTransport,
        *,
        base_url: str | None = None,
        deadline_seconds: float = 10.0,
    ) -> None:
        if type(transport) is not httpx2.MockTransport:
            raise ModelProtocolError("Only recorded fixture transport is supported")
        if type(deadline_seconds) not in {float, int} or not 0 < deadline_seconds <= 10:
            raise ModelProtocolError("Invalid fixture deadline")
        self.provider: Provider = provider
        self.base_url: str = normalize_base_url(provider, base_url)
        self.transport: httpx2.MockTransport = transport
        self.deadline_seconds: float = deadline_seconds

    def _codec(self) -> ModelCodec:
        from terminus.model_gateway.compatible import OpenAICompatibleCodec
        from terminus.model_gateway.native import AnthropicCodec, GeminiCodec

        if self.provider == "anthropic":
            return AnthropicCodec()
        if self.provider == "gemini":
            return GeminiCodec()
        return OpenAICompatibleCodec(provider=self.provider)

    @staticmethod
    def _error(model: str, code: str) -> ModelResponse:
        return ModelResponse(status="error", model=model, error_code=code)

    async def respond(self, request: ModelRequest) -> ModelResponse:
        """No retries, credential lookup, admission policy or external calls."""
        try:
            request = ModelRequest.model_validate(request.model_dump())
            codec = self._codec()
            payload = codec.encode(request)
            bounded_json(payload)
            url = self.base_url.rstrip("/") + "/" + codec.path(request).lstrip("/")
            headers = dict(codec.headers)
            if self.provider == "anthropic":
                headers["x-api-key"] = "fixture-key-not-a-credential"
            elif self.provider == "gemini":
                headers["x-goog-api-key"] = "fixture-key-not-a-credential"
            else:
                headers["Authorization"] = "Bearer fixture-key-not-a-credential"
            async with asyncio.timeout(self.deadline_seconds):
                async with httpx2.AsyncClient(
                    transport=self.transport, follow_redirects=False, trust_env=False
                ) as client:
                    async with client.stream(
                        "POST", url, json=payload, headers=headers
                    ) as response:
                        if response.status_code != 200:
                            code = {
                                400: "unsupported_request",
                                401: "authentication_denied",
                                403: "authentication_denied",
                                422: "unsupported_request",
                                429: "rate_limited",
                            }.get(response.status_code, "provider_unavailable")
                            return self._error(request.model, code)
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            if len(content) + len(chunk) > 1048576:
                                return self._error(request.model, "response_too_large")
                            content.extend(chunk)
                        raw = parse_json_object(
                            bytes(content).decode("utf-8"), limit=1048576
                        )
                        return validate_response(codec.decode(raw, request), request)
        except TimeoutError:
            return self._error(request.model, "timeout_unknown_usage")
        except httpx2.HTTPError:
            return self._error(request.model, "transport_unknown_usage")
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return self._error(request.model, "invalid_provider_contract")
