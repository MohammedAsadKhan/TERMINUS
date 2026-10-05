# ruff: noqa: F811
"""Production boundaries with simulated provider I/O; no paid/provider traffic."""

from __future__ import annotations

import asyncio
import json
import ssl

import pytest
from pydantic import SecretStr

from terminus.model_gateway.admission import ModelAdmissionDeniedError
from terminus.model_gateway.evaluation import valid_live_transport
from terminus.model_gateway.live import (
    LiveModelExecutor,
    ModelTransportError,
    ProductionModelTransport,
    _LivePermit,
    _destination,
)
from terminus.model_gateway.models import ModelConnectionCreate
from terminus.model_gateway.policy import ModelPolicyWrite, PolicyGrant
from terminus.model_gateway.secrets import CredentialCipher
from terminus.model_gateway.store import ModelConnectionStore
from tests.test_model_admission import setup  # noqa: F401
from tests.test_model_evaluation import make, provider
from tests.test_model_routing import budget_store


async def private_dns(host):
    return ("10.0.0.2",)


def wire_payload():
    return json.dumps(
        {
            "model": "fixture-model",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": '{"verdict":"benign"}'},
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
        }
    ).encode()


async def prepare(setup):
    return await setup[0].prepare(
        setup[1],
        "admin",
        setup[3].connection_id,
        "fixture-model",
        (setup[2].evidence_id,),
    )


def transport(setup, **kwargs):
    return ProductionModelTransport(setup[3], setup[0].connections, "admin", **kwargs)


@pytest.mark.asyncio
async def test_direct_transport_is_forbidden_without_financial_and_scheduler_gate(
    setup,
):
    client = transport(setup)
    assert valid_live_transport(client)
    with pytest.raises(ModelTransportError, match="gated"):
        await client.respond((await prepare(setup)).request)


@pytest.mark.asyncio
async def test_live_attempt_has_private_payload_single_use_and_intent_before_io(
    setup, monkeypatch
):
    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)
    calls = []

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        assert setup[7].fetchone("SELECT 1 FROM model_live_attempts") is not None
        assert (
            setup[7].fetchone(
                "SELECT 1 FROM model_admission_audit WHERE outcome='live_intent_before_io'"
            )
            is not None
        )
        assert b"evidence-secret" not in body
        calls.append((address, path, body))
        permit.io_started = True
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    call = await prepare(setup)
    result = await LiveModelExecutor(setup[0], budget_store(setup)).execute(
        call, transport(setup), "admin"
    )
    assert result.response.output == {"verdict": "benign"}
    assert result.reservation.state == "settled"
    assert calls[0][:2] == ("10.0.0.2", "/chat/completions")
    with pytest.raises(ModelAdmissionDeniedError):
        await setup[0].respond_live(
            call, transport(setup), reservation_id=result.reservation.reservation_id
        )
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "revoke", ["membership", "connection", "policy", "evidence", "cancel", "budget"]
)
async def test_revocation_while_provider_pending_cancels_and_retains_exposure(
    setup, monkeypatch, revoke
):
    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)
    stopped = asyncio.Event()
    budgets = budget_store(setup)

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        permit.io_started = True
        db = setup[7]
        if revoke == "membership":
            db.execute("DELETE FROM memberships WHERE org_id='org' AND user_id='admin'")
        elif revoke == "connection":
            db.execute("UPDATE model_connections SET enabled=0 WHERE org_id='org'")
        elif revoke == "policy":
            current = setup[5].get("org", "admin")
            setup[5].put(
                "org",
                "admin",
                ModelPolicyWrite(expected_version=current.version, grants=()),
            )
        elif revoke == "evidence":
            setup[5].classify_evidence(
                "org", "admin", setup[2].evidence_id, "redacted_cloud"
            )
        elif revoke == "cancel":
            setup[0].scheduler.request_cancel("org", setup[1].task_id)
        else:
            db.execute("UPDATE model_budgets SET version=version+1")
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    with pytest.raises(ModelAdmissionDeniedError):
        await LiveModelExecutor(setup[0], budgets).execute(
            await prepare(setup), transport(setup), "admin"
        )
    assert stopped.is_set()
    assert (
        setup[7].fetchone("SELECT state FROM model_reservations")["state"]
        == "ambiguous"
    )
    assert setup[7].fetchone(
        "SELECT outcome FROM model_admission_audit WHERE outcome='live_denied_unknown'"
    )


@pytest.mark.asyncio
async def test_evaluation_final_recheck_prevents_live_verified_after_immediate_revocation(
    setup, monkeypatch
):
    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        permit.io_started = True
        setup[7].execute("UPDATE model_connections SET enabled=0 WHERE org_id='org'")
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    service = make(setup)
    records = await service.run(
        "org",
        "admin",
        provider(setup),
        live_transports=lambda conn: ProductionModelTransport(
            conn, setup[0].connections, "admin"
        ),
    )
    assert not any(record.state == "live_verified" for record in records)
    assert any(
        record.track == "live" and record.state == "policy_denied" for record in records
    )


@pytest.mark.asyncio
async def test_deadline_and_external_cancellation_keep_cost_unknown(setup, monkeypatch):
    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        permit.io_started = True
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    result = await LiveModelExecutor(setup[0], budget_store(setup)).execute(
        await prepare(setup), transport(setup, timeout_seconds=0.02), "admin"
    )
    assert result.response.error_code == "timeout_unknown_usage"
    assert result.reservation.state == "ambiguous"
    assert cancelled.is_set()
    cancelled.clear()
    entered.clear()
    task = asyncio.create_task(
        LiveModelExecutor(setup[0], budget_store(setup)).execute(
            await prepare(setup), transport(setup), "admin"
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cancelled.is_set()
    assert all(
        row["state"] == "ambiguous"
        for row in setup[7].fetchall("SELECT state FROM model_reservations")
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("169.254.169.254",),
        ("10.0.0.1",),
        ("8.8.8.8", "10.0.0.1"),
        ("::ffff:8.8.8.8",),
        ("224.0.0.1",),
        ("100.100.100.200",),
    ],
)
async def test_hosted_destination_rejects_entire_unsafe_dns_set(
    setup, monkeypatch, addresses
):
    async def dns(host):
        return addresses

    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", dns)
    with pytest.raises(ModelTransportError):
        await _destination(setup[4], await prepare(setup))


@pytest.mark.asyncio
async def test_private_dns_change_blocks_transport_before_send(setup, monkeypatch):
    async def dns(host):
        return ("10.0.0.3",)

    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", dns)
    with pytest.raises(ModelTransportError):
        await _destination(setup[3], await prepare(setup))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    [
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.test\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
    ],
)
async def test_redirect_compression_oversize_and_ambiguous_framing_denied(setup, wire):
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    with pytest.raises(ModelTransportError):
        await transport(setup)._read_response(reader)


@pytest.mark.asyncio
async def test_response_chunk_body_is_bounded(setup):
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
    )
    reader.feed_eof()
    assert await transport(setup)._read_response(reader) == (200, b"test")


@pytest.mark.asyncio
async def test_google_repeated_vary_headers_are_valid(setup):
    reader = asyncio.StreamReader()
    reader.feed_data(
        b"HTTP/1.1 200 OK\r\nVary: Origin\r\nVary: X-Origin\r\n"
        b"Vary: Referer\r\nContent-Length: 4\r\n\r\ntest"
    )
    reader.feed_eof()
    assert await transport(setup)._read_response(reader) == (200, b"test")


@pytest.mark.asyncio
async def test_transport_diagnostics_do_not_log_exception_secrets(
    setup, monkeypatch, caplog
):
    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)

    async def exchange(self, endpoint, address, path, headers, body, permit):
        raise OSError("api-key=never-log-this-secret")

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    result = await LiveModelExecutor(setup[0], budget_store(setup)).execute(
        await prepare(setup), transport(setup), "admin"
    )
    assert result.response.error_code == "transport_unknown_usage"
    assert "stage=http_exchange" in caplog.text
    assert "never-log-this-secret" not in caplog.text


@pytest.mark.asyncio
async def test_credential_envelope_resolved_only_into_internal_headers(
    setup, monkeypatch
):
    cipher = CredentialCipher.from_key(
        CredentialCipher.generate_key().get_secret_value()
    )
    connections = ModelConnectionStore(setup[7], cipher)
    setup[0].connections = connections
    connection = connections.create(
        "org",
        "admin",
        ModelConnectionCreate(
            name="Authenticated",
            provider="openai",
            models=["fixture-model"],
            enabled=True,
            api_key=SecretStr("fixture-private-key"),
        ),
    )
    policy = setup[5].get("org", "admin")
    setup[5].put(
        "org",
        "admin",
        ModelPolicyWrite(
            expected_version=policy.version,
            grants=(
                *policy.grants,
                PolicyGrant(
                    role="triage",
                    connection_id=connection.connection_id,
                    connection_version=connection.version,
                    models=("fixture-model",),
                    classifications=("redacted_cloud",),
                ),
            ),
        ),
    )
    setup[5].classify_evidence("org", "admin", setup[2].evidence_id, "redacted_cloud")
    budgets = budget_store(setup)
    budgets.put_price(
        "org",
        "admin",
        connection.connection_id,
        "fixture-model",
        input_per_mtok_micro_usd=1000000,
        output_per_mtok_micro_usd=1000000,
    )

    async def dns(host):
        assert host == "api.openai.com"
        return ("8.8.8.8",)

    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", dns)
    seen = []

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        assert headers["Authorization"] == "Bearer fixture-private-key"
        assert b"fixture-private-key" not in body
        assert b"max_completion_tokens" in body
        seen.append(address)
        permit.io_started = True
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    call = await setup[0].prepare(
        setup[1],
        "admin",
        connection.connection_id,
        "fixture-model",
        (setup[2].evidence_id,),
    )
    result = await LiveModelExecutor(setup[0], budgets).execute(
        call, ProductionModelTransport(connection, connections, "admin"), "admin"
    )
    assert result.response.status == "ok"
    assert seen == ["8.8.8.8"]
    assert "fixture-private-key" not in str(
        setup[7].fetchall("SELECT * FROM model_admission_audit")
    )


@pytest.mark.asyncio
async def test_numeric_socket_pin_preserves_https_sni_and_certificate_validation(
    setup, monkeypatch
):
    call = await prepare(setup)
    permit = _LivePermit(call, lambda: None)
    pinned = []
    loop = asyncio.get_running_loop()

    async def connect(sock, address):
        pinned.append(address)

    monkeypatch.setattr(loop, "sock_connect", connect)
    reader = asyncio.StreamReader()
    reader.feed_data(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    reader.feed_eof()

    class Writer:
        def write(self, wire):
            assert b"Host: models.corp.test" in wire

        async def drain(self):
            pass

        def close(self):
            pass

    async def opening(**kwargs):
        assert kwargs["server_hostname"] == "models.corp.test"
        assert kwargs["ssl"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["ssl"].check_hostname is True
        kwargs["sock"].close()
        return reader, Writer()

    monkeypatch.setattr(asyncio, "open_connection", opening)
    assert await transport(setup)._exchange(
        setup[3].base_url, "10.0.0.2", "/chat/completions", {}, b"{}", permit
    ) == (200, b"{}")
    assert pinned == [("10.0.0.2", 443)]


@pytest.mark.asyncio
async def test_real_loopback_socket_obeys_registered_path_and_one_request(setup):
    """An actual local HTTP socket exercises framing without any provider call."""
    seen = []

    async def server(reader, writer):
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            length = int(
                next(
                    line.split(b":", 1)[1]
                    for line in header.split(b"\r\n")
                    if line.startswith(b"Content-Length:")
                )
            )
            body = await reader.readexactly(length)
            seen.append((header, body))
            assert setup[7].fetchone("SELECT 1 FROM model_live_attempts")
            payload = wire_payload()
            writer.write(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                + f"{len(payload):x}\r\n".encode()
                + payload
                + b"\r\n0\r\n\r\n"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    listener = await asyncio.start_server(server, "127.0.0.1", 0)
    try:
        port = listener.sockets[0].getsockname()[1]
        connections = setup[0].connections
        connection = connections.create(
            "org",
            "admin",
            ModelConnectionCreate(
                name="Loopback",
                provider="local",
                base_url=f"http://127.0.0.1:{port}/v1",
                models=["fixture-model"],
                enabled=True,
            ),
        )
        policy = setup[5].get("org", "admin")
        setup[5].put(
            "org",
            "admin",
            ModelPolicyWrite(
                expected_version=policy.version,
                grants=(
                    *policy.grants,
                    PolicyGrant(
                        role="triage",
                        connection_id=connection.connection_id,
                        connection_version=connection.version,
                        models=("fixture-model",),
                        classifications=("local_only",),
                    ),
                ),
            ),
        )
        budgets = budget_store(setup)
        budgets.put_price(
            "org",
            "admin",
            connection.connection_id,
            "fixture-model",
            input_per_mtok_micro_usd=1000000,
            output_per_mtok_micro_usd=1000000,
        )
        call = await setup[0].prepare(
            setup[1],
            "admin",
            connection.connection_id,
            "fixture-model",
            (setup[2].evidence_id,),
        )
        result = await LiveModelExecutor(setup[0], budgets).execute(
            call, ProductionModelTransport(connection, connections, "admin"), "admin"
        )
        assert result.response.output == {"verdict": "benign"}
        assert result.reservation.state == "settled"
        assert len(seen) == 1
        assert seen[0][0].startswith(b"POST /v1/chat/completions HTTP/1.1\r\n")
        assert f"Host: 127.0.0.1:{port}".encode() in seen[0][0]
        assert b"evidence-secret" not in seen[0][1]
    finally:
        listener.close()
        await listener.wait_closed()


@pytest.mark.asyncio
async def test_registered_actor_and_connection_snapshot_required_before_io(
    setup, monkeypatch
):
    called = []

    async def exchange(*args):
        called.append(True)
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    with pytest.raises(ModelAdmissionDeniedError):
        await LiveModelExecutor(setup[0], budget_store(setup)).execute(
            await prepare(setup),
            ProductionModelTransport(setup[3], setup[0].connections, "member"),
            "admin",
        )
    assert called == []


@pytest.mark.asyncio
async def test_released_reservation_is_denied_without_provider_payload(
    setup, monkeypatch
):
    from terminus.model_gateway.ledger import ReservationRequest

    called = []

    async def exchange(*args):
        called.append(True)
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    budgets = budget_store(setup)
    call = await prepare(setup)
    reservation = budgets.reserve(
        "org",
        "admin",
        ReservationRequest(
            idempotency_key="unused",
            incident_id=call.incident_id,
            task_id=call.task_id,
            run_id=call.run_id,
            connection_id=call.connection_id,
            connection_version=call.connection_version,
            model=call.request.model,
            request_bytes=len(call.request.model_dump_json().encode()),
            max_output_tokens=call.request.max_output_tokens,
        ),
    )
    budgets.release("org", reservation.reservation_id)
    with pytest.raises(ModelAdmissionDeniedError):
        await setup[0].respond_live(
            call, transport(setup), reservation_id=reservation.reservation_id
        )
    assert called == []


@pytest.mark.asyncio
async def test_lowered_budget_before_transport_gate_denies_send(setup):
    from terminus.model_gateway.ledger import ReservationRequest

    call = await prepare(setup)
    budgets = budget_store(setup)
    reservation = budgets.reserve(
        "org",
        "admin",
        ReservationRequest(
            idempotency_key="lowered",
            incident_id=call.incident_id,
            task_id=call.task_id,
            run_id=call.run_id,
            connection_id=call.connection_id,
            connection_version=call.connection_version,
            model=call.request.model,
            request_bytes=len(call.request.model_dump_json().encode()),
            max_output_tokens=call.request.max_output_tokens,
        ),
    )
    setup[7].execute("UPDATE model_budgets SET limit_micro_usd=0,version=version+1")
    with pytest.raises(ModelAdmissionDeniedError):
        await setup[0].respond_live(
            call, transport(setup), reservation_id=reservation.reservation_id
        )
    assert not setup[7].fetchall("SELECT 1 FROM model_live_attempts")


@pytest.mark.asyncio
async def test_one_reservation_cannot_fund_a_second_prepared_payload(
    setup, monkeypatch
):
    from terminus.model_gateway.ledger import ReservationRequest

    monkeypatch.setattr("terminus.model_gateway.live.resolve_addresses", private_dns)
    sends = []

    async def exchange(self, endpoint, address, path, headers, body, permit):
        permit.check()
        permit.io_started = True
        sends.append(body)
        return 200, wire_payload()

    monkeypatch.setattr(ProductionModelTransport, "_exchange", exchange)
    budgets = budget_store(setup)
    call = await prepare(setup)
    reservation = budgets.reserve(
        "org",
        "admin",
        ReservationRequest(
            idempotency_key="one-reservation",
            incident_id=call.incident_id,
            task_id=call.task_id,
            run_id=call.run_id,
            connection_id=call.connection_id,
            connection_version=call.connection_version,
            model=call.request.model,
            request_bytes=len(call.request.model_dump_json().encode()),
            max_output_tokens=call.request.max_output_tokens,
        ),
    )
    await setup[0].respond_live(
        call, transport(setup), reservation_id=reservation.reservation_id
    )
    with pytest.raises(ModelAdmissionDeniedError):
        await setup[0].respond_live(
            await prepare(setup),
            transport(setup),
            reservation_id=reservation.reservation_id,
        )
    assert len(sends) == 1
