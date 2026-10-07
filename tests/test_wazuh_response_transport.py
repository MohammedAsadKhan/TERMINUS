import asyncio
import json
from ipaddress import IPv4Address

import httpx2
import pytest
from pydantic import SecretStr, ValidationError

from terminus.response.wazuh_transport import WazuhBlockRequest, WazuhResponseTransport
from terminus.toolkit.wazuh_readers import WazuhManagerSettings


def request(**changes):
    return WazuhBlockRequest.model_validate(
        dict(
            org_id="org-lab",
            intent_id="intent-1",
            proposal_digest="a" * 64,
            agent_id="001",
            source_ip=IPv4Address("10.77.0.10"),
            duration_seconds=60,
            **changes,
        )
    )


def adapter(handler):
    return WazuhResponseTransport(
        WazuhManagerSettings(
            org_id="org-lab",
            manager_url="https://manager.test",
            username=SecretStr("response-user"),
            password=SecretStr("secret"),
        ),
        allowed_agent_id="001",
        allowed_source_ip=IPv4Address("10.77.0.10"),
        transport=httpx2.MockTransport(handler),
    )


def test_fixed_command_and_acknowledgement_not_verification():
    calls = []

    def handler(req):
        calls.append(req)
        if req.method == "POST":
            return httpx2.Response(200, json={"error": 0, "data": {"token": "token"}})
        assert req.url.params["agents_list"] == "001"
        body = json.loads(req.content)
        assert body["command"] == "!terminus-ip-block"
        assert body["alert"]["data"]["terminus_intent_id"] == "intent-1"
        return httpx2.Response(
            200,
            json={
                "error": 0,
                "data": {
                    "affected_items": ["001"],
                    "total_affected_items": 1,
                    "total_failed_items": 0,
                },
            },
        )

    result = asyncio.run(adapter(handler).dispatch(request()))
    assert result.status == "acknowledged"
    assert not result.verified
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [("org_id", "foreign"), ("agent_id", "002"), ("source_ip", "192.168.56.1")],
)
def test_scope_denied_before_io(field, value):
    def handler(req):
        pytest.fail("Scope denial must perform no I/O")

    original = request().model_dump()
    original[field] = IPv4Address(value) if field == "source_ip" else value
    result = asyncio.run(
        adapter(handler).dispatch(WazuhBlockRequest.model_validate(original))
    )
    assert result.status == "denied"


def test_timeout_after_send_is_unknown_no_retry():
    calls = []

    def handler(req):
        calls.append(req)
        if req.method == "POST":
            return httpx2.Response(200, json={"error": 0, "data": {"token": "token"}})
        raise httpx2.ReadTimeout("secret provider body", request=req)

    result = asyncio.run(adapter(handler).dispatch(request()))
    assert result.status == "unknown"
    assert "secret" not in result.model_dump_json()
    assert len(calls) == 2


@pytest.mark.parametrize(
    "body",
    [b"x" * 65537, b"{}", b'{"data":[]}'],
    ids=["oversized", "missing", "malformed"],
)
def test_untrusted_auth_output_is_unavailable(body):
    result = asyncio.run(
        adapter(lambda req: httpx2.Response(200, content=body)).dispatch(request())
    )
    assert result.status == "unavailable"


def test_models_cannot_supply_commands_or_manager_agent():
    for changes in (
        {"command": "shell"},
        {"agent_id": "000"},
        {"duration_seconds": 901},
    ):
        data = request().model_dump()
        data.update(changes)
        with pytest.raises(ValidationError):
            WazuhBlockRequest.model_validate(data)
