"""Payload redaction and endpoint-locality regression tests."""

from __future__ import annotations

import asyncio
import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import JsonValue, ValidationError
from typing import cast

from terminus.model_gateway.safety import (
    DataSafetyError,
    EndpointVerifier,
    VerifiedDestination,
    redact_json,
    redact_text,
)


def test_text_redacts_credentials_and_personal_identifiers() -> None:
    sensitive = (
        "Bearer opaque-access-value Basic user:arbitrary-password "
        "sk-proj-abcdefghijklmno AIzaSyA123456789012345678901234567890 "
        "ghp_abcdefghijklmnopqrstuvwxyz person@example.com 123-45-6789 "
        "4111 1111 1111 1111"
    )
    result = redact_text(sensitive)
    for raw in sensitive.split():
        if raw not in {"Bearer", "Basic"}:
            assert raw not in result
    assert result.count("[REDACTED]") >= 8


def test_private_keys_cookies_and_raw_json_are_redacted() -> None:
    payload = (
        "Cookie: session=raw-cookie\n"
        "-----BEGIN PRIVATE KEY-----\nraw-key\n-----END PRIVATE KEY-----\n"
        '{"password":{"nested":"raw-password"},"message":"person@example.com"}'
    )
    result = redact_text(payload)
    assert "raw-cookie" not in result
    assert "raw-key" not in result
    assert "raw-password" not in result
    assert "person@example.com" not in result


def test_structured_secret_fields_replace_the_entire_nested_value() -> None:
    value: dict[str, JsonValue] = {
        "api_key": {"nested": ["otherwise", "retained"]},
        "profile": {"email": "person@example.com", "note": "safe"},
        "tool_args": '{"client_secret":{"deep":"do-not-retain"}}',
    }
    assert redact_json(value) == {
        "api_key": "[REDACTED]",
        "profile": {"email": "[REDACTED]", "note": "safe"},
        "tool_args": '{"client_secret":"[REDACTED]"}',
    }


def test_sanitized_key_collisions_and_invalid_json_values_fail_generically() -> None:
    with pytest.raises(DataSafetyError, match=r"^Data safety validation failed$"):
        _ = redact_json({"first@example.com": 1, "second@example.com": 2})
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(DataSafetyError, match=r"^Data safety validation failed$"):
        _ = redact_json(cast("JsonValue", cyclic))
    with pytest.raises(DataSafetyError, match=r"^Data safety validation failed$"):
        _ = redact_json(float("nan"))


def test_payload_limits_are_bounded() -> None:
    with pytest.raises(DataSafetyError):
        _ = redact_text("x" * 65537)
    too_deep: object = "leaf"
    for _ in range(14):
        too_deep = [too_deep]
    with pytest.raises(DataSafetyError):
        _ = redact_json(cast("JsonValue", too_deep))
    with pytest.raises(DataSafetyError):
        _ = redact_json({"password": "x" * 65537})


class Clock:
    current: datetime

    def __init__(self) -> None:
        self.current = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.current


@pytest.mark.asyncio
async def test_private_literal_bypasses_resolver_and_is_bound() -> None:
    called = False

    async def resolver(_host: str) -> tuple[str, ...]:
        nonlocal called
        called = True
        return ("8.8.8.8",)

    clock = Clock()
    verifier = EndpointVerifier(resolver, clock)
    record = await verifier.verify("HTTPS://[fd00::1]:443/v1")
    assert called is False
    assert record.endpoint == "https://[fd00::1]/v1"
    assert record.addresses == ("fd00::1",)
    verifier.validate(record, "https://[fd00::1]/v1")
    with pytest.raises(DataSafetyError):
        verifier.validate(record, "https://[fd00::1]/v2")


@pytest.mark.asyncio
async def test_dns_requires_every_answer_to_be_explicitly_private() -> None:
    answers = {
        "localhost": ("127.0.0.1", "::1"),
        "models.internal": ("10.2.3.4", "fd00::20"),
        "mixed.internal": ("10.2.3.4", "8.8.8.8"),
    }

    async def resolver(host: str) -> tuple[str, ...]:
        return answers[host]

    verifier = EndpointVerifier(resolver)
    localhost = await verifier.verify("http://localhost:8080/v1")
    assert localhost.addresses == ("127.0.0.1", "::1")
    private = await verifier.verify("https://models.internal/v1")
    assert private.addresses == ("10.2.3.4", "fd00::20")
    with pytest.raises(DataSafetyError):
        _ = await verifier.verify("https://mixed.internal/v1")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://10.0.0.1/v1",
        "https://user:pass@10.0.0.1/v1",
        "https://10.0.0.1/v1?token=value",
        "https://10.0.0.1/v1#fragment",
        "https://10.0.0.1:99999/v1",
        "https://169.254.169.254/latest/meta-data",
        "https://192.0.0.1/v1",
        "https://198.51.100.1/v1",
        "https://[::ffff:8.8.8.8]/v1",
    ],
)
async def test_invalid_and_nonlocal_endpoints_fail(endpoint: str) -> None:
    async def resolver(_host: str) -> tuple[str, ...]:
        return ("10.0.0.1",)

    with pytest.raises(DataSafetyError):
        _ = await EndpointVerifier(resolver).verify(endpoint)


@pytest.mark.asyncio
async def test_expiry_rebinding_and_forged_records_fail_closed() -> None:
    clock = Clock()
    current = ("10.0.0.1",)

    async def resolver(_host: str) -> tuple[str, ...]:
        return current

    verifier = EndpointVerifier(resolver, clock, ttl_seconds=30)
    old = await verifier.verify("https://models.internal/v1")
    current = ("10.0.0.2",)
    fresh = await verifier.verify("https://models.internal/v1")
    assert old.addresses != fresh.addresses
    assert old.addresses == ("10.0.0.1",)
    assert fresh.addresses == ("10.0.0.2",)
    clock.current += timedelta(seconds=30)
    with pytest.raises(DataSafetyError):
        verifier.validate(old, old.endpoint)

    with pytest.raises(ValidationError) as caught:
        _ = VerifiedDestination(
            endpoint="https://models.internal/v1",
            addresses=("8.8.8.8",),
            verified_at=clock.current,
            expires_at=clock.current + timedelta(seconds=30),
        )
    assert "8.8.8.8" not in str(caught.value)


@pytest.mark.asyncio
async def test_resolver_timeout_is_generic_and_cancellation_propagates() -> None:
    async def slow(_host: str) -> tuple[str, ...]:
        _ = await asyncio.Event().wait()
        return ("10.0.0.1",)

    verifier = EndpointVerifier(slow, resolver_timeout=0.01)
    with pytest.raises(DataSafetyError, match=r"^Data safety validation failed$"):
        _ = await verifier.verify("https://models.internal/v1")

    pending = asyncio.create_task(
        EndpointVerifier(slow).verify("https://models.internal/v1")
    )
    await asyncio.sleep(0)
    _ = pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending


@pytest.mark.asyncio
async def test_mapped_private_ipv4_is_allowed_but_unsafe_classes_are_not() -> None:
    async def resolver(_host: str) -> tuple[str, ...]:
        return ("::ffff:192.168.1.10",)

    record = await EndpointVerifier(resolver).verify("https://models.internal/v1")
    assert [ipaddress.ip_address(addr) for addr in record.addresses] == [
        ipaddress.ip_address("::ffff:192.168.1.10")
    ]

    for address in ("0.0.0.0", "224.0.0.1", "fe80::1", "2001:db8::1"):

        async def unsafe(_host: str, answer: str = address) -> tuple[str, ...]:
            return (answer,)

        with pytest.raises(DataSafetyError):
            _ = await EndpointVerifier(unsafe).verify("https://models.internal/v1")
