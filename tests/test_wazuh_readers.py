"""Fixture transport checks for bounded and honest investigation collectors."""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta

import httpx2
import pytest
from pydantic import SecretStr, ValidationError

from terminus.toolkit.models import ReadQuery
from terminus.toolkit.sources import EndpointResource
from terminus.toolkit.wazuh_readers import (
    WazuhIndexerReader,
    WazuhIndexerSettings,
    WazuhManagerReader,
    WazuhManagerSettings,
)

STAMP = datetime(2026, 10, 4, 12, 30, tzinfo=UTC)
RESOURCE = EndpointResource(org_id="org-1", resource_id="endpoint-1", agent_id="001")


def query(kind="detection", **changes):
    return ReadQuery(
        resource_id="endpoint-1",
        start=STAMP - timedelta(minutes=30),
        end=STAMP + timedelta(minutes=30),
        event_kind=kind,
        **changes,
    )


def manager_settings(**changes):
    return WazuhManagerSettings(
        org_id="org-1",
        manager_url="https://manager.test:55000",
        username=SecretStr("manager-user"),
        password=SecretStr("manager-secret"),
        **changes,
    )


def indexer_settings(**changes):
    return WazuhIndexerSettings(
        org_id="org-1",
        indexer_url="https://indexer.test:9200",
        username=SecretStr("indexer-user"),
        password=SecretStr("indexer-secret"),
        **changes,
    )


def hit(event_id="event-1", agent="001", **source):
    return {
        "_id": event_id,
        "_index": "wazuh-alerts-4.x-2026.10.04",
        "sort": [
            int(STAMP.timestamp() * 1000),
            "manager-1",
            event_id,
            "wazuh-alerts-4.x-2026.10.04",
        ],
        "_source": {
            "agent": {"id": agent},
            "timestamp": STAMP.isoformat(),
            "manager": {"name": "manager-1"},
            "id": event_id,
            "rule": {"groups": ["authentication_failed"]},
            **source,
        },
    }


def page(items=(), total=None, **extra):
    return {
        "timed_out": False,
        "_shards": {"failed": 0},
        "hits": {
            "total": {
                "value": len(items) if total is None else total,
                "relation": "eq",
            },
            "hits": list(items),
        },
        **extra,
    }


@pytest.mark.asyncio
async def test_indexer_uses_scoped_fixed_authentication_query_and_own_credentials():
    requests = []

    def transport(request):
        requests.append(request)
        return httpx2.Response(200, json=page([hit()]))

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        reader = WazuhIndexerReader(indexer_settings(), client)
        result = await reader.read(query("authentication"), RESOURCE)
    assert result.status == "ok"
    assert result.coverage == "complete"
    assert result.observations[0].source_timestamp == STAMP
    request = requests[0]
    assert str(request.url) == "https://indexer.test:9200/wazuh-alerts-*/_search"
    assert request.method == "POST"
    assert (
        request.headers["Authorization"]
        == "Basic " + base64.b64encode(b"indexer-user:indexer-secret").decode()
    )
    body = json.loads(request.content)
    assert body["query"]["bool"]["filter"] == [
        {"term": {"agent.id": "001"}},
        {
            "range": {
                "timestamp": {
                    "gte": query().start.isoformat(),
                    "lte": query().end.isoformat(),
                }
            }
        },
        {"terms": {"rule.groups": ["authentication_failed", "authentication_success"]}},
    ]
    assert body["track_total_hits"] is True
    assert body["sort"] == [
        {"timestamp": "asc"},
        {"manager.name": "asc"},
        {"id": "asc"},
        {"_index": "asc"},
    ]
    assert "indexer-secret" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_manager_authenticates_raw_jwt_and_returns_only_observed_connectivity():
    requests = []

    def transport(request):
        requests.append(request)
        if request.url.path == "/security/user/authenticate":
            assert request.url.params["raw"] == "true"
            return httpx2.Response(200, text="fixture.jwt.token")
        assert request.headers["Authorization"] == "Bearer fixture.jwt.token"
        assert request.url.params["agents_list"] == "001"
        assert request.url.params["sort"] == "+id"
        return httpx2.Response(
            200,
            json={
                "error": 0,
                "data": {
                    "total_affected_items": 1,
                    "affected_items": [
                        {
                            "id": "001",
                            "name": "host-1",
                            "status": "active",
                            "lastKeepAlive": STAMP.isoformat(),
                        }
                    ],
                },
            },
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhManagerReader(manager_settings(), client).read(
            query("inventory"), RESOURCE
        )
    assert result.status == "ok"
    assert result.observations[0].data["connectivity"] == "active"
    assert "healthy" not in result.model_dump_json()
    assert (
        requests[0].headers["Authorization"]
        == "Basic " + base64.b64encode(b"manager-user:manager-secret").decode()
    )
    assert requests[1].url.host == "manager.test"


@pytest.mark.parametrize(
    "data",
    [
        {"id": "001", "status": "active"},
        {
            "id": "001",
            "status": "active",
            "lastKeepAlive": (STAMP - timedelta(hours=2)).isoformat(),
        },
    ],
)
@pytest.mark.asyncio
async def test_missing_or_stale_manager_heartbeat_is_a_gap(data):
    def transport(request):
        if "authenticate" in request.url.path:
            return httpx2.Response(200, text="token")
        return httpx2.Response(
            200,
            json={
                "error": 0,
                "data": {"affected_items": [data], "total_affected_items": 1},
            },
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhManagerReader(manager_settings(), client).read(
            query("coverage"), RESOURCE
        )
    assert result.status == "partial"
    assert result.observations == ()
    assert result.coverage == "incomplete"
    assert result.gaps


@pytest.mark.parametrize(
    "fault",
    [
        "timed_out",
        "failed_shards",
        "missing_shards",
        "missing_total",
        "inexact_total",
        "short_page",
    ],
)
@pytest.mark.asyncio
async def test_indexer_incomplete_responses_cannot_claim_empty_or_complete(fault):
    payload = page()
    if fault == "timed_out":
        payload["timed_out"] = True
    elif fault == "failed_shards":
        payload["_shards"] = {"failed": 1}
    elif fault == "missing_shards":
        del payload["_shards"]
    elif fault == "missing_total":
        del payload["hits"]["total"]
    elif fault == "inexact_total":
        payload["hits"]["total"]["relation"] = "gte"
    else:
        payload["hits"]["total"]["value"] = 2
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, json=payload)
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "partial"
    assert result.coverage == "incomplete"
    assert result.gaps


@pytest.mark.asyncio
async def test_complete_empty_is_distinct_from_incomplete():
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, json=page())
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "empty"
    assert result.coverage == "complete"


@pytest.mark.parametrize(
    "bad_hit",
    [
        hit(agent="999"),
        hit(timestamp=(STAMP + timedelta(hours=2)).isoformat()),
        hit(rule={"groups": ["not_authentication"]}),
    ],
)
@pytest.mark.asyncio
async def test_foreign_or_out_of_scope_response_discards_whole_collection(bad_hit):
    requests = []

    def transport(request):
        requests.append(request)
        return httpx2.Response(
            200, json=page([hit()] if len(requests) == 1 else [bad_hit], total=2)
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query("authentication", page_size=1), RESOURCE
        )
    assert result.status == "error"
    assert result.observations == ()


@pytest.mark.asyncio
async def test_pagination_uses_search_after_and_explicit_page_bound():
    bodies = []

    def transport(request):
        bodies.append(json.loads(request.content))
        return httpx2.Response(200, json=page([hit(f"event-{len(bodies)}")], total=5))

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(page_size=1, max_pages=4), RESOURCE
        )
    assert len(bodies) == 4
    assert "search_after" not in bodies[0]
    assert bodies[1]["search_after"] == hit("event-1")["sort"]
    assert result.status == "partial"
    assert result.truncated
    assert len(result.observations) == 4


@pytest.mark.asyncio
async def test_transient_failure_retains_observed_first_page_as_partial():
    calls = 0

    def transport(request):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise httpx2.ReadTimeout("fixture timeout")
        return httpx2.Response(200, json=page([hit()], total=2))

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(page_size=1), RESOURCE
        )
    assert result.status == "partial"
    assert len(result.observations) == 1


@pytest.mark.asyncio
async def test_total_deadline_cancels_slow_stream_without_unbounded_wait(monkeypatch):
    monkeypatch.setattr("terminus.toolkit.wazuh_readers._TOTAL_TIMEOUT", 0.02)

    async def transport(request):
        await asyncio.Event().wait()
        return httpx2.Response(200, json=page())

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "unavailable"
    assert result.observations == ()
    assert "deadline" in result.gaps[0]


@pytest.mark.parametrize(
    "data",
    [
        {"affected_items": [], "total_failed_items": 1, "total_affected_items": 0},
        {"affected_items": []},
    ],
)
@pytest.mark.asyncio
async def test_manager_failed_or_missing_total_cannot_claim_empty(data):
    def transport(request):
        if "authenticate" in request.url.path:
            return httpx2.Response(200, text="token")
        return httpx2.Response(200, json={"error": 0, "data": data})

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhManagerReader(manager_settings(), client).read(
            query("coverage"), RESOURCE
        )
    assert result.status == "partial"
    assert result.coverage == "incomplete"
    assert result.observations == ()


@pytest.mark.asyncio
async def test_manager_foreign_agent_is_not_retained():
    def transport(request):
        if "authenticate" in request.url.path:
            return httpx2.Response(200, text="token")
        return httpx2.Response(
            200,
            json={
                "error": 0,
                "data": {
                    "total_affected_items": 1,
                    "affected_items": [
                        {"id": "999", "lastKeepAlive": STAMP.isoformat()}
                    ],
                },
            },
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        result = await WazuhManagerReader(manager_settings(), client).read(
            query("inventory"), RESOURCE
        )
    assert result.status == "error"
    assert result.observations == ()


@pytest.mark.asyncio
async def test_stream_bound_precedes_json_parse_and_stops_consumption():
    consumed = []

    class Chunks(httpx2.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(10):
                consumed.append(True)
                yield b"x" * 20000

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, stream=Chunks())
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert len(consumed) == 4
    assert result.status == "partial"
    assert result.truncated
    assert result.observations == ()


@pytest.mark.asyncio
async def test_observation_output_limit_leaves_evidence_envelope_headroom():
    payload = page([hit("one", full_log="x" * 20000), hit("two", full_log="y" * 20000)])
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, json=payload)
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "partial"
    assert result.truncated
    assert len(result.observations) == 1
    assert len(result.model_dump_json().encode()) < 32768


@pytest.mark.asyncio
async def test_foreign_record_after_output_bound_discards_entire_provider_page():
    payload = page(
        [
            hit("one", full_log="x" * 20000),
            hit("two", full_log="y" * 20000),
            hit("foreign", agent="999"),
        ]
    )
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(200, json=payload)
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "error"
    assert result.observations == ()


@pytest.mark.asyncio
async def test_redirects_are_not_followed_even_when_client_default_follows():
    calls = []

    def transport(request):
        calls.append(request)
        return httpx2.Response(302, headers={"Location": "https://foreign.test"})

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(transport), follow_redirects=True
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert len(calls) == 1
    assert result.status == "unavailable"
    assert result.observations == ()


@pytest.mark.asyncio
async def test_cancellation_propagates_without_invented_result():
    started = asyncio.Event()

    async def transport(request):
        started.set()
        await asyncio.Event().wait()
        return httpx2.Response(200, json=page())

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        task = asyncio.create_task(
            WazuhIndexerReader(indexer_settings(), client).read(query(), RESOURCE)
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.parametrize(
    "changes", [{"org_id": "other-org"}, {"resource_id": "other-resource"}]
)
@pytest.mark.asyncio
async def test_untrusted_scope_is_rejected_before_network(changes):
    resource = RESOURCE.model_copy(update=changes)

    def transport(request):
        raise AssertionError("No out-of-scope request may reach transport")

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(transport)) as client:
        with pytest.raises(ValueError, match="binding mismatch"):
            await WazuhIndexerReader(indexer_settings(), client).read(query(), resource)


@pytest.mark.asyncio
async def test_unsafe_provider_ids_are_bound_to_index_and_hashed():
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(
            lambda request: httpx2.Response(
                200, json=page([hit("unsafe/id?"), hit("x" * 201)])
            )
        )
    ) as client:
        result = await WazuhIndexerReader(indexer_settings(), client).read(
            query(), RESOURCE
        )
    assert result.status == "ok"
    assert all(
        item.source_event_id.startswith("alert:") for item in result.observations
    )
    assert len({item.source_event_id for item in result.observations}) == 2


def test_settings_separate_connection_identity_and_mask_credentials():
    manager = manager_settings()
    indexer = indexer_settings()
    assert manager.connector_id == "wazuh_manager"
    assert indexer.connector_id == "wazuh_indexer"
    assert manager.verify_tls
    assert indexer.verify_tls
    for settings in (manager, indexer):
        assert "username" not in settings.model_dump()
        assert "password" not in settings.model_dump()
        assert "secret" not in repr(settings)
    with pytest.raises(ValidationError):
        manager_settings(connector_id="wazuh_indexer")


@pytest.mark.parametrize(
    "url",
    [
        "http://manager.test",
        "https://user:pass@manager.test",
        "https://manager.test/base",
        "https://manager.test?query=1",
        "https://manager.test#fragment",
    ],
)
def test_connector_origin_rejects_insecure_or_ambiguous_urls(url):
    with pytest.raises(ValidationError):
        WazuhManagerSettings(
            org_id="org-1",
            manager_url=url,
            username=SecretStr("user"),
            password=SecretStr("secret"),
        )
