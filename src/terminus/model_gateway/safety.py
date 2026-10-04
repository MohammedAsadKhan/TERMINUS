# pyright: reportImplicitStringConcatenation=false

"""Bounded payload redaction and private-destination verification."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import ClassVar, cast, final
from urllib.parse import unquote, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, JsonValue, field_validator, model_validator

_MAX_BYTES = 64 * 1024
_MAX_DEPTH = 12
_MAX_NODES = 10_000
_REDACTED = "[REDACTED]"


class DataSafetyError(ValueError):
    """A payload or destination failed a data-safety boundary."""


def _failure() -> DataSafetyError:
    return DataSafetyError("Data safety validation failed")


_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.DOTALL,
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic)\s+[^\s,;\"']+")
_COOKIE_HEADER = re.compile(r"(?im)^(set-cookie|cookie)\s*:\s*[^\r\n]*")
_COOKIE_VALUE = re.compile(
    r"(?i)\b(cookie|session(?:id)?|session[_-]?token)\s*([:=])\s*"
    r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s;,}\]]+)"
)
_ASSIGNED_SECRET = re.compile(
    r"(?i)(?P<label>[\"']?(?:api[ _-]?key|access[ _-]?key|client[ _-]?secret|"
    r"password|passwd|pwd|secret|auth(?:orization)?[ _-]?token|token|credential)"
    r"[\"']?\s*[:=]\s*)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}\]]+)"
)
_VENDOR_SECRET = re.compile(
    r"(?<![A-Za-z0-9_-])(?:"
    r"sk-(?:proj-|ant-(?:api\d{2}-)?|svcacct-)?[A-Za-z0-9_-]{8,}|"
    r"AIza[A-Za-z0-9_-]{20,}|"
    r"github_pat_[A-Za-z0-9_]{10,}|gh[pousr]_[A-Za-z0-9]{10,}|"
    r"xox(?:a|b|p|r|s)-[A-Za-z0-9-]{8,}|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|"
    r"hf_[A-Za-z0-9]{10,}"
    r")(?![A-Za-z0-9_-])",
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)
_SSN = re.compile(r"(?<!\d)(?:\d{3}-\d{2}-\d{4}|\d{9})(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_SECRET_KEY = re.compile(
    r"(?:^|[_\-. ])(?:api[_\-. ]?key|access[_\-. ]?key|private[_\-. ]?key|"
    r"client[_\-. ]?secret|password(?:hash)?|passwd|pwd|secret|"
    r"(?:(?:access|refresh|auth|id|bearer)[_\-. ]?)?token|authorization|"
    r"credential|cookies?|set[_\-. ]?cookie|session(?:[_\-. ]?(?:id|token))?)"
    r"(?:$|[_\-. ])",
    re.IGNORECASE,
)


def _luhn(candidate: re.Match[str]) -> str:
    raw = candidate.group(0)
    digits = "".join(character for character in raw if character.isdigit())
    if not 13 <= len(digits) <= 19:
        return raw
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return _REDACTED if total % 10 == 0 else raw


def _plain_text(text: str) -> str:
    redacted = _PRIVATE_KEY.sub(_REDACTED, text)
    redacted = _COOKIE_HEADER.sub(
        lambda match: f"{match.group(1)}: {_REDACTED}", redacted
    )
    redacted = _AUTH.sub(lambda match: f"{match.group(1)} {_REDACTED}", redacted)
    redacted = _COOKIE_VALUE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{_REDACTED}", redacted
    )
    redacted = _ASSIGNED_SECRET.sub(
        lambda match: f"{match.group('label')}{_REDACTED}", redacted
    )
    redacted = _VENDOR_SECRET.sub(_REDACTED, redacted)
    redacted = _EMAIL.sub(_REDACTED, redacted)
    redacted = _SSN.sub(_REDACTED, redacted)
    return _CARD.sub(_luhn, redacted)


@final
class _WalkState:
    __slots__: ClassVar[tuple[str, ...]] = ("ancestors", "bytes_seen", "nodes")

    def __init__(self) -> None:
        self.ancestors: set[int] = set()
        self.bytes_seen = 0
        self.nodes = 0

    def consume(self, value: str = "") -> None:
        self.nodes += 1
        self.bytes_seen += len(value.encode("utf-8"))
        if self.nodes > _MAX_NODES or self.bytes_seen > _MAX_BYTES:
            raise _failure()


def _json_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise _failure()
        result[key] = value
    return result


def _load_embedded(text: str) -> JsonValue | None:
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return cast(
            "JsonValue",
            json.loads(
                stripped,
                object_pairs_hook=_json_pairs,
                parse_constant=lambda _value: (_ for _ in ()).throw(_failure()),
            ),
        )
    except DataSafetyError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _walk(  # noqa: C901, PLR0911, PLR0912
    value: object, depth: int, state: _WalkState
) -> JsonValue:
    if depth > _MAX_DEPTH:
        raise _failure()
    if value is None or isinstance(value, bool):
        state.consume()
        return value
    if isinstance(value, int):
        state.consume(str(value))
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _failure()
        state.consume(repr(value))
        return value
    if isinstance(value, str):
        state.consume(value)
        embedded = _load_embedded(value)
        if embedded is None:
            return _plain_text(value)
        cleaned = _walk(embedded, depth + 1, state)
        encoded = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > _MAX_BYTES:
            raise _failure()
        return encoded
    if not isinstance(value, (dict, list)):
        raise _failure()

    container = cast("dict[object, object] | list[object]", value)
    identity = id(container)
    if identity in state.ancestors:
        raise _failure()
    state.ancestors.add(identity)
    state.consume()
    try:
        if isinstance(container, list):
            return [_walk(item, depth + 1, state) for item in container]

        output: dict[str, JsonValue] = {}
        for raw_key, item in container.items():
            if not isinstance(raw_key, str):
                raise _failure()
            state.consume(raw_key)
            key = _plain_text(raw_key)
            if key in output:
                raise _failure()
            if _SECRET_KEY.search(raw_key):
                _ = _walk(item, depth + 1, state)
                output[key] = _REDACTED
            else:
                output[key] = _walk(item, depth + 1, state)
        return output
    finally:
        state.ancestors.remove(identity)


def _ensure_output_size(value: JsonValue) -> JsonValue:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )
    except (TypeError, ValueError, OverflowError):
        raise _failure() from None
    if len(encoded.encode("utf-8")) > _MAX_BYTES:
        raise _failure()
    return value


def redact_json(value: JsonValue) -> JsonValue:
    """Return a bounded JSON value with recognizable sensitive material removed."""
    try:
        return _ensure_output_size(_walk(value, 0, _WalkState()))
    except DataSafetyError:
        raise
    except (RecursionError, UnicodeError, ValueError, TypeError, OverflowError):
        raise _failure() from None


def redact_text(text: str) -> str:
    """Redact recognizable secrets and personal identifiers from bounded text."""
    try:
        if not isinstance(text, str) or len(text.encode("utf-8")) > _MAX_BYTES:  # pyright: ignore[reportUnnecessaryIsInstance]
            raise _failure()
        parsed = _load_embedded(text)
        if parsed is None:
            result = _plain_text(text)
        else:
            result = json.dumps(
                redact_json(parsed), ensure_ascii=False, separators=(",", ":")
            )
        if len(result.encode("utf-8")) > _MAX_BYTES:
            raise _failure()
    except DataSafetyError:
        raise
    except (RecursionError, UnicodeError, ValueError, TypeError):
        raise _failure() from None
    return result


_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_ULA = ipaddress.ip_network("fc00::/7")


def _safe_address(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not raw or raw != raw.strip() or "%" in raw:
        raise _failure()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        raise _failure() from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        _ = _safe_address(str(address.ipv4_mapped))
        return address
    allowed = address.is_loopback
    if isinstance(address, ipaddress.IPv4Address):
        allowed = allowed or any(address in network for network in _RFC1918)
    else:
        allowed = allowed or address in _ULA
    if not allowed:
        raise _failure()
    return address


def _address_sort_key(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[int, int]:
    return address.version, int(address)


def _canonical_addresses(addresses: object) -> tuple[str, ...]:
    if not isinstance(addresses, tuple):
        raise _failure()
    raw_addresses = cast("tuple[object, ...]", addresses)
    if (
        not raw_addresses
        or len(raw_addresses) > 64
        or any(not isinstance(item, str) for item in raw_addresses)
    ):
        raise _failure()
    parsed = [_safe_address(cast("str", item)) for item in raw_addresses]
    canonical = tuple(str(item) for item in sorted(parsed, key=_address_sort_key))
    if len(set(canonical)) != len(canonical):
        raise _failure()
    return canonical


def _canonical_endpoint(endpoint: str) -> tuple[str, str]:
    if (
        not isinstance(endpoint, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        or not endpoint
        or endpoint != endpoint.strip()
        or len(endpoint.encode("utf-8")) > 2048
        or any(ord(character) < 33 or ord(character) == 127 for character in endpoint)
    ):
        raise _failure()
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        raise _failure() from None
    if port is not None and port < 1:
        raise _failure()
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise _failure()
    hostname = parsed.hostname.rstrip(".").lower()
    if (
        not hostname
        or "\\" in endpoint
        or any(
            ord(character) < 33 or ord(character) == 127
            for character in unquote(parsed.path)
        )
    ):
        raise _failure()
    try:
        host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise _failure() from None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
        if not re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            host,
        ):
            raise _failure() from None
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    shown_host = f"[{host}]" if literal is not None and literal.version == 6 else host
    authority = shown_host if port in {None, default_port} else f"{shown_host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), authority, path, "", "")), host


class VerifiedDestination(BaseModel):
    """A short-lived binding between an endpoint and explicitly safe addresses."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True, strict=True, extra="forbid", hide_input_in_errors=True
    )

    endpoint: str
    addresses: tuple[str, ...]
    verified_at: datetime
    expires_at: datetime

    @field_validator("verified_at", "expires_at")
    @classmethod
    def aware_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("destination verification is invalid")
        return value

    @model_validator(mode="after")
    def valid_binding(self) -> VerifiedDestination:
        canonical, _ = _canonical_endpoint(self.endpoint)
        addresses = _canonical_addresses(self.addresses)
        if (
            canonical != self.endpoint
            or addresses != self.addresses
            or self.expires_at <= self.verified_at
            or self.expires_at - self.verified_at > timedelta(seconds=60)
        ):
            raise ValueError("destination verification is invalid")
        return self


Resolver = Callable[[str], Awaitable[tuple[str, ...]]]
Clock = Callable[[], datetime]


def _seconds(value: object, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= maximum
    ):
        raise _failure()
    return float(value)


@final
class EndpointVerifier:
    """Resolve endpoints through an injected resolver and bind private addresses."""

    def __init__(
        self,
        resolver: Resolver,
        clock: Clock | None = None,
        ttl_seconds: float = 30,
        resolver_timeout: float = 1,
    ) -> None:
        self._resolver = resolver
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ttl = _seconds(ttl_seconds, 60)
        self._resolver_timeout = _seconds(resolver_timeout, 2)

    def _now(self) -> datetime:
        try:
            current = self._clock()
        except Exception:
            raise _failure() from None
        if (
            not isinstance(current, datetime)  # pyright: ignore[reportUnnecessaryIsInstance]
            or current.tzinfo is None
            or current.utcoffset() is None
        ):
            raise _failure()
        return current

    async def verify(self, endpoint: str) -> VerifiedDestination:
        """Return a fresh binding after every address is explicitly classified safe."""
        canonical, host = _canonical_endpoint(endpoint)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            addresses = (str(_safe_address(host)),)
        else:
            try:
                async with asyncio.timeout(self._resolver_timeout):
                    resolved = await self._resolver(host)
            except TimeoutError:
                raise _failure() from None
            except Exception:
                raise _failure() from None
            addresses = _canonical_addresses(resolved)
        now = self._now()
        try:
            return VerifiedDestination(
                endpoint=canonical,
                addresses=addresses,
                verified_at=now,
                expires_at=now + timedelta(seconds=self._ttl),
            )
        except (TypeError, ValueError):
            raise _failure() from None

    def validate(self, record: VerifiedDestination, endpoint: str) -> None:
        """Validate freshness and exact endpoint/address binding without network I/O."""
        try:
            checked = _validated_record(record)
            canonical, _ = _canonical_endpoint(endpoint)
        except (TypeError, ValueError):
            raise _failure() from None
        now = self._now()
        if (
            checked.endpoint != canonical
            or checked.addresses != _canonical_addresses(checked.addresses)
            or now >= checked.expires_at
            or checked.verified_at > now
        ):
            raise _failure()


def _validated_record(value: object) -> VerifiedDestination:
    if not isinstance(value, VerifiedDestination):
        raise _failure()
    return VerifiedDestination.model_validate(value.model_dump())


__all__ = [
    "DataSafetyError",
    "EndpointVerifier",
    "VerifiedDestination",
    "redact_json",
    "redact_text",
]
