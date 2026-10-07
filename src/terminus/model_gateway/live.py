"""Explicitly configured, pinned, bounded provider I/O behind model admission.

No credentials, environment proxies, redirects, SDK retries or provider traffic
are used at construction time. Calling ``respond`` directly is deliberately
unsupported: scheduler admission and durable financial intent own every call.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import math
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, final
from urllib.parse import urlsplit
from uuid import uuid4

from terminus.model_gateway.compatible import OpenAICompatibleCodec
from terminus.model_gateway.contracts import (
    ModelProtocolError,
    ModelRequest,
    ModelResponse,
    parse_json_object,
    validate_response,
)
from terminus.model_gateway.ledger import (
    ModelBudgetStore,
    ModelReservation,
    ReservationRequest,
    UsageReport,
)
from terminus.model_gateway.models import ModelConnectionView, normalize_base_url
from terminus.model_gateway.native import AnthropicCodec, GeminiCodec
from terminus.model_gateway.safety import (
    EndpointVerifier,
    _canonical_endpoint,
)
from terminus.model_gateway.store import ModelConnectionStore

if TYPE_CHECKING:
    from terminus.model_gateway.admission import (
        ModelAdmissionService,
        PreparedModelCall,
    )


class ModelTransportError(ValueError):
    """Safe transport failure with no credential, URL, request or response body."""


class _ResponseTooLargeError(ModelTransportError):
    pass


_logger = logging.getLogger(__name__)


async def resolve_addresses(host: str) -> tuple[str, ...]:
    """Resolve once; callers pin a numeric address from the complete result."""
    results = await asyncio.get_running_loop().getaddrinfo(
        host, None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    return tuple(sorted({str(item[4][0]) for item in results}))


async def _destination(
    connection: ModelConnectionView, call: PreparedModelCall
) -> tuple[str, str]:
    endpoint = normalize_base_url(connection.provider, connection.base_url)
    canonical, host = _canonical_endpoint(endpoint)
    if connection.provider == "local":
        verifier = EndpointVerifier(resolve_addresses)
        fresh = await verifier.verify(endpoint)
        if call.destination is None or fresh.addresses != call.destination.addresses:
            raise ModelTransportError("Model destination changed")
        return canonical, fresh.addresses[0]
    if urlsplit(canonical).scheme != "https":
        raise ModelTransportError("Hosted models require HTTPS")
    async with asyncio.timeout(2):
        addresses = await resolve_addresses(host)
    if not addresses or len(addresses) > 64:
        raise ModelTransportError("Model destination denied")
    for raw in addresses:
        if "%" in raw:
            raise ModelTransportError("Model destination denied")
        address = ipaddress.ip_address(raw)
        if (
            not address.is_global
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or (
                isinstance(address, ipaddress.IPv6Address)
                and (
                    address.ipv4_mapped is not None
                    or address.sixtofour is not None
                    or address.teredo is not None
                )
            )
        ):
            raise ModelTransportError("Model destination denied")
    return canonical, str(ipaddress.ip_address(addresses[0]))


@dataclass
class _LivePermit:
    """Private execution binding; never serialized or accepted from model args."""

    call: PreparedModelCall
    check: Callable[[], None] = field(repr=False)
    io_started: bool = False
    used: bool = False


@dataclass(frozen=True)
class LiveExecutionResult:
    response: ModelResponse
    reservation: ModelReservation


@final
class ProductionModelTransport:
    """One registered connection using existing provider codecs and verified TLS."""

    def __init__(
        self,
        connection: ModelConnectionView,
        connections: ModelConnectionStore,
        actor_user_id: str,
        *,
        timeout_seconds: float = 30,
        response_limit: int = 262144,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 120
            or type(response_limit) is not int
            or not 1024 <= response_limit <= 1048576
        ):
            raise ModelTransportError("Invalid transport bounds")
        self.connection = ModelConnectionView.model_validate(
            connection.model_dump()
        ).model_copy(deep=True)
        self.connections = connections
        self.actor_user_id = actor_user_id
        self.timeout_seconds = timeout_seconds
        self.response_limit = response_limit

    async def respond(self, request: ModelRequest) -> ModelResponse:
        """Reject direct use without scheduler, evidence and budget admission."""
        _ = request
        raise ModelTransportError("Model transport requires gated execution")

    async def _execute(self, permit: _LivePermit) -> ModelResponse:  # noqa: C901  # pyright: ignore[reportUnusedFunction] - consumed only by the private admission gate
        if type(permit) is not _LivePermit or permit.used:
            raise ModelTransportError("Model execution permit is unavailable")
        permit.used = True
        request = permit.call.request
        codec = (
            AnthropicCodec()
            if self.connection.provider == "anthropic"
            else GeminiCodec()
            if self.connection.provider == "gemini"
            else OpenAICompatibleCodec(self.connection.provider)
        )
        stage = "destination"
        try:
            async with asyncio.timeout(self.timeout_seconds):
                permit.check()
                endpoint, address = await _destination(self.connection, permit.call)
                stage = "request_encoding"
                body = json.dumps(
                    codec.encode(request),
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode()
                if len(body) > 65536:
                    raise ModelTransportError("Model request is oversized")
                # Credentials are resolved after DNS and current ownership checks.
                # They stay in this request's internal headers and never in JSON.
                permit.check()
                stage = "credential_resolution"
                secret = self.connections.resolve_transport_credential(
                    self.connection, self.actor_user_id
                )
                headers = codec.headers
                if secret is not None:
                    value = secret.get_secret_value()
                    if any(ord(char) < 33 or ord(char) > 126 for char in value):
                        raise ModelTransportError("Model credential is invalid")
                    if urlsplit(endpoint).scheme != "https":
                        raise ModelTransportError(
                            "Credential transmission requires HTTPS"
                        )
                    header = {"anthropic": "x-api-key", "gemini": "x-goog-api-key"}.get(
                        self.connection.provider, "Authorization"
                    )
                    headers[header] = (
                        value if header != "Authorization" else "Bearer " + value
                    )
                stage = "http_exchange"
                status, raw = await self._exchange(
                    endpoint, address, codec.path(request), headers, body, permit
                )
                if status != 200:
                    _logger.warning("Model provider returned HTTP status=%s", status)
                    code = (
                        "rate_limited"
                        if status == 429
                        else "authentication_denied"
                        if status in {401, 403}
                        else "provider_unavailable"
                        if status >= 500
                        else "unsupported_request"
                    )
                    return ModelResponse(
                        status="error", model=request.model, error_code=code
                    )
                stage = "response_decoding"
                payload = parse_json_object(
                    raw.decode("utf-8"), limit=self.response_limit
                )
                return validate_response(codec.decode(payload, request), request)
        except asyncio.CancelledError:
            raise
        except _ResponseTooLargeError:
            return ModelResponse(
                status="error", model=request.model, error_code="response_too_large"
            )
        except TimeoutError:
            _logger.warning(
                "Model transport timed out: stage=%s deadline_seconds=%s io_started=%s",
                stage,
                self.timeout_seconds,
                permit.io_started,
            )
            return ModelResponse(
                status="error", model=request.model, error_code="timeout_unknown_usage"
            )
        except (ModelProtocolError, UnicodeError):
            return ModelResponse(
                status="error",
                model=request.model,
                error_code="invalid_provider_contract",
            )
        except (OSError, ModelTransportError, ValueError) as exc:
            # Admission denials must propagate and abort approved fallback.
            from terminus.model_gateway.admission import ModelAdmissionDeniedError

            if isinstance(exc, ModelAdmissionDeniedError):
                raise
            # Never log exception text, headers, bodies, credentials or URLs.
            # These fixed parser reasons are generated locally, not by providers.
            safe_reason = (
                {
                    "Invalid provider HTTP response": "invalid_http_response",
                    "Invalid provider HTTP framing": "invalid_http_framing",
                    "Provider trailers are unsupported": "unsupported_http_trailers",
                    "Compressed provider responses are unsupported": "compressed_response",
                    "Provider redirect denied": "redirect_denied",
                }.get(str(exc), "unspecified")
                if isinstance(exc, ModelTransportError)
                else "unspecified"
            )
            _logger.warning(
                "Model transport failed: stage=%s exception=%s reason=%s io_started=%s",
                stage,
                type(exc).__name__,
                safe_reason,
                permit.io_started,
            )
            return ModelResponse(
                status="error",
                model=request.model,
                error_code="transport_unknown_usage",
            )

    async def _exchange(
        self,
        endpoint: str,
        address: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        permit: _LivePermit,
    ) -> tuple[int, bytes]:
        parsed = urlsplit(endpoint)
        host = parsed.hostname
        if (
            host is None
            or not path.startswith("/")
            or any(ord(char) < 33 or ord(char) > 126 for char in path)
        ):
            raise ModelTransportError("Model destination denied")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        request_path = parsed.path.rstrip("/") + path
        authority = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            authority += f":{parsed.port}"
        request_headers = {
            "Host": authority,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Connection": "close",
            "Content-Length": str(len(body)),
            **headers,
        }
        wire = (
            f"POST {request_path} HTTP/1.1\r\n"
            + "".join(f"{key}: {value}\r\n" for key, value in request_headers.items())
            + "\r\n"
        ).encode("ascii") + body
        literal = ipaddress.ip_address(address)
        family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)  # noqa: FBT003
        writer: asyncio.StreamWriter | None = None
        try:
            # sock_connect sees a literal; no hostname resolution can rebind it.
            await asyncio.get_running_loop().sock_connect(sock, (str(literal), port))
            if parsed.scheme == "https":
                reader, writer = await asyncio.open_connection(
                    sock=sock,
                    limit=16384,
                    ssl=ssl.create_default_context(),
                    server_hostname=host,
                )
            else:
                reader, writer = await asyncio.open_connection(sock=sock, limit=16384)
            permit.check()  # Last revocation check after TCP/TLS, before payload.
            permit.io_started = True
            writer.write(wire)
            await writer.drain()
            return await self._read_response(reader)
        finally:
            if writer is None:
                sock.close()
            else:
                writer.close()

    async def _read_response(self, reader: asyncio.StreamReader) -> tuple[int, bytes]:  # noqa: C901, PLR0912
        try:
            header = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            raise ModelTransportError("Invalid provider HTTP response") from None
        if len(header) > 16384:
            raise _ResponseTooLargeError("Provider headers exceed bound")
        lines = header[:-4].split(b"\r\n")
        parts = lines[0].split(b" ", 2)
        if (
            len(parts) < 2
            or parts[0] not in {b"HTTP/1.1", b"HTTP/1.0"}
            or not parts[1].isdigit()
            or len(parts[1]) != 3
        ):
            raise ModelTransportError("Invalid provider HTTP response")
        status = int(parts[1])
        if not 200 <= status <= 599:
            raise ModelTransportError("Invalid provider HTTP response")
        fields: dict[bytes, bytes] = {}
        for line in lines[1:]:
            key, separator, value = line.partition(b":")
            key = key.lower()
            if (
                not separator
                or (key in fields and key != b"vary")
                or not key
                or any(char <= 32 or char >= 127 for char in key)
            ):
                raise ModelTransportError("Invalid provider HTTP response")
            if key == b"vary" and key in fields:
                fields[key] += b", " + value.strip()
            else:
                fields[key] = value.strip()
        if fields.get(b"content-encoding", b"identity").lower() != b"identity":
            raise ModelTransportError("Compressed provider responses are unsupported")
        # Redirects are terminal; never process Location or send a second request.
        if 300 <= status < 400:
            raise ModelTransportError("Provider redirect denied")
        if b"transfer-encoding" in fields:
            if (
                b"content-length" in fields
                or fields[b"transfer-encoding"].lower() != b"chunked"
            ):
                raise ModelTransportError("Invalid provider HTTP framing")
            raw = await self._read_chunks(reader)
        elif b"content-length" in fields:
            length = fields[b"content-length"]
            if not length.isdigit() or len(length) > 10:
                raise ModelTransportError("Invalid provider HTTP framing")
            count = int(length)
            if count > self.response_limit:
                raise _ResponseTooLargeError("Provider response exceeds bound")
            raw = await reader.readexactly(count)
        else:
            chunks: list[bytes] = []
            size = 0
            while chunk := await reader.read(
                min(16384, self.response_limit + 1 - size)
            ):
                size += len(chunk)
                if size > self.response_limit:
                    raise _ResponseTooLargeError("Provider response exceeds bound")
                chunks.append(chunk)
            raw = b"".join(chunks)
        return status, raw

    async def _read_chunks(self, reader: asyncio.StreamReader) -> bytes:
        output = bytearray()
        chunks = 0
        while True:
            line = await reader.readuntil(b"\r\n")
            chunks += 1
            if len(line) > 128 or chunks > 8192:
                raise ModelTransportError("Invalid provider HTTP framing")
            token = line[:-2].split(b";", 1)[0]
            if not token or any(
                char not in b"0123456789abcdefABCDEF" for char in token
            ):
                raise ModelTransportError("Invalid provider HTTP framing")
            count = int(token, 16)
            if len(output) + count > self.response_limit:
                raise _ResponseTooLargeError("Provider response exceeds bound")
            if count == 0:
                # No trailers; bounded conservative HTTP subset.
                if await reader.readexactly(2) != b"\r\n":
                    raise ModelTransportError("Provider trailers are unsupported")
                return bytes(output)
            output.extend(await reader.readexactly(count))
            if await reader.readexactly(2) != b"\r\n":
                raise ModelTransportError("Invalid provider HTTP framing")


@final
class LiveModelExecutor:
    """Budget reservation plus the same revocable admission gate used by routing."""

    def __init__(
        self, admission: ModelAdmissionService, budgets: ModelBudgetStore
    ) -> None:
        if admission.scheduler.db is not budgets.db:
            raise ModelTransportError("Model services require one database")
        self.admission = admission
        self.budgets = budgets

    async def execute(
        self,
        call: PreparedModelCall,
        transport: ProductionModelTransport,
        actor_user_id: str,
    ) -> LiveExecutionResult:
        await self.admission.authorize(call)
        reservation = self.budgets.reserve(
            call.org_id,
            actor_user_id,
            ReservationRequest(
                idempotency_key=f"live:{uuid4()}",
                incident_id=call.incident_id,
                task_id=call.task_id,
                run_id=call.run_id,
                connection_id=call.connection_id,
                connection_version=call.connection_version,
                model=call.request.model,
                request_bytes=len(call.request.model_dump_json().encode()),
                max_output_tokens=call.request.max_output_tokens,
                max_input_tokens=65536,
            ),
        )
        rid = reservation.reservation_id
        try:
            response = await self.admission.respond_live(
                call, transport, reservation_id=rid
            )
        except BaseException:
            with contextlib.suppress(Exception):
                _ = self.budgets.mark_ambiguous(call.org_id, rid)
            raise
        usage = response.usage
        try:
            settled = self.budgets.settle(
                call.org_id,
                rid,
                UsageReport(
                    input_tokens=usage.input_tokens,
                    output_tokens=usage.output_tokens,
                    cached_input_tokens=usage.cached_input_tokens,
                    reasoning_tokens=usage.reasoning_tokens,
                )
                if response.status != "error"
                else UsageReport(),
            )
        except Exception:
            settled = self.budgets.mark_ambiguous(
                call.org_id, rid, reason_code="settle_failed"
            )
        return LiveExecutionResult(response, settled)
