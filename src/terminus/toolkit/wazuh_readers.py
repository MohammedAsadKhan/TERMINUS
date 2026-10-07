"""Bounded, read-only Wazuh manager and indexer adapters.

Only server-owned endpoint mappings and named queries reach these readers. Raw
provider bodies are bounded before JSON parsing; credentials never enter output.
"""

from __future__ import annotations

import asyncio
import hashlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Literal, cast, override
from urllib.parse import urlsplit

import httpx2
from pydantic import Field, JsonValue, SecretStr, TypeAdapter, field_validator

from terminus.toolkit.models import Contract, Id, ReadQuery
from terminus.toolkit.sources import EndpointResource, ReadCollection, ReadObservation

_MAX_BYTES = 65536
_MAX_OBSERVATION_BYTES = 32768
_TOTAL_TIMEOUT = 10
_JSON = TypeAdapter[JsonValue](JsonValue)


class _Connection(Contract):
    org_id: Id
    connector_version: Id = "1.0"
    username: SecretStr = Field(repr=False, exclude=True)
    password: SecretStr = Field(repr=False, exclude=True)
    verify_tls: bool = True

    @field_validator("username", "password")
    @classmethod
    def nonempty_secret(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value():
            raise ValueError("Connector credentials are required")
        return value

    @field_validator("manager_url", "indexer_url", check_fields=False)
    @classmethod
    def trusted_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("Connector URL must be an HTTPS origin")
        return value.rstrip("/")


class WazuhManagerSettings(_Connection):
    manager_url: str
    connector_id: Literal["wazuh_manager"] = "wazuh_manager"


class WazuhIndexerSettings(_Connection):
    indexer_url: str
    connector_id: Literal["wazuh_indexer"] = "wazuh_indexer"


class _InvalidResponseError(ValueError):
    """Untrusted response must be rejected, including preceding pages."""


class _ByteLimitError(ValueError):
    """Provider body exceeds the total decoded wire budget."""


class _WireBudget:
    def __init__(self) -> None:
        self.remaining: int = _MAX_BYTES
        self.observations: list[ReadObservation] = []
        self.output_bytes: int = 0

    def observe(self, observation: ReadObservation) -> bool:
        size = len(observation.model_dump_json().encode())
        if self.output_bytes + size > _MAX_OBSERVATION_BYTES:
            return False
        self.output_bytes += size
        self.observations.append(observation)
        return True

    async def consume(self, response: httpx2.Response) -> bytes:
        _ = response.raise_for_status()
        if response.is_redirect:
            raise _InvalidResponseError("Redirect rejected")
        chunks: list[bytes] = []
        async for chunk in response.aiter_bytes():
            if len(chunk) > self.remaining:
                raise _ByteLimitError("Provider body exceeds 64 KiB")
            self.remaining -= len(chunk)
            chunks.append(chunk)
        return b"".join(chunks)


def _object(value: object) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise _InvalidResponseError("Expected an object")
    return cast("dict[str, JsonValue]", value)


def _items(value: object, maximum: int) -> list[dict[str, JsonValue]]:
    if not isinstance(value, list) or len(cast("list[object]", value)) > maximum:
        raise _InvalidResponseError("Invalid page")
    return [_object(item) for item in cast("list[object]", value)]


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise _InvalidResponseError("Missing source timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise _InvalidResponseError("Source timestamp requires timezone")
    return parsed.astimezone(UTC)


def _collection(
    observations: list[ReadObservation], gaps: list[str], *, truncated: bool = False
) -> ReadCollection:
    return ReadCollection(
        status="partial" if gaps else ("ok" if observations else "empty"),
        observations=tuple(observations),
        coverage="incomplete" if gaps else "complete",
        truncated=truncated,
        gaps=tuple(dict.fromkeys(gaps)),
    )


def _request_failure(budget: _WireBudget, gap: str) -> ReadCollection:
    if budget.observations:
        return _collection(budget.observations, [gap])
    return ReadCollection(status="unavailable", gaps=(gap,))


def _manager_observation(
    item: dict[str, JsonValue],
    query: ReadQuery,
    resource: EndpointResource,
    gaps: list[str],
    seen: set[str],
) -> ReadObservation | None:
    if item.get("id") != resource.agent_id:
        raise _InvalidResponseError("Manager returned a foreign agent")
    if resource.agent_id in seen:
        raise _InvalidResponseError("Manager repeated an agent")
    seen.add(resource.agent_id)
    if not item.get("lastKeepAlive"):
        gaps.append("Agent context has no source heartbeat timestamp")
        return None
    stamp = _timestamp(item.get("lastKeepAlive"))
    if not query.start <= stamp <= query.end:
        gaps.append("Agent lastKeepAlive is outside the requested window")
        return None
    return ReadObservation(
        source_id="wazuh-manager",
        source_event_id=f"agent:{resource.agent_id}",
        source_timestamp=stamp,
        data={
            "agent_id": resource.agent_id,
            "name": item.get("name"),
            "connectivity": item.get("status"),
            "last_keep_alive": item.get("lastKeepAlive"),
            "os": item.get("os"),
            "version": item.get("version"),
        },
    )


def _indexer_total(payload: dict[str, JsonValue], gaps: list[str]) -> int | None:
    if payload.get("timed_out") is not False:
        gaps.append("Indexer timed out or omitted timeout status")
    shards = _object(payload.get("_shards", {}))
    if type(shards.get("failed")) is not int or shards["failed"] != 0:
        gaps.append("Indexer shards failed or shard status is unknown")
    total = _object(payload.get("hits")).get("total")
    if (
        isinstance(total, dict)
        and type(total.get("value")) is int
        and cast("int", total["value"]) >= 0
    ):
        if total.get("relation") != "eq":
            gaps.append("Indexer total is not exact")
        return cast("int", total["value"])
    if type(total) is int and total >= 0:
        return total
    gaps.append("Indexer did not supply a valid total")
    return None


def _indexer_observation(
    item: dict[str, JsonValue],
    query: ReadQuery,
    resource: EndpointResource,
    seen: set[tuple[str, str]],
) -> ReadObservation:
    source = _object(item.get("_source"))
    if _object(source.get("agent")).get("id") != resource.agent_id:
        raise _InvalidResponseError("Indexer returned a foreign agent")
    stamp = _timestamp(source.get("timestamp"))
    if not query.start <= stamp <= query.end:
        raise _InvalidResponseError("Indexer returned an out-of-window event")
    index, event_id = item.get("_index"), item.get("_id")
    if (
        not isinstance(index, str)
        or not index.startswith("wazuh-alerts-")
        or not isinstance(event_id, str)
    ):
        raise _InvalidResponseError("Invalid alert identity")
    identity = (index, event_id)
    if identity in seen:
        raise _InvalidResponseError("Indexer repeated an event")
    seen.add(identity)
    if query.event_kind == "authentication":
        groups = _object(source.get("rule")).get("groups")
        if not isinstance(groups, list) or not any(
            group in ("authentication_failed", "authentication_success")
            for group in groups
        ):
            raise _InvalidResponseError("Indexer returned a non-authentication event")
    source_event_id = (
        "alert:" + hashlib.sha256(f"{index}:{event_id}".encode()).hexdigest()
    )
    return ReadObservation(
        source_id="wazuh-indexer",
        source_event_id=source_event_id,
        source_timestamp=stamp,
        data={"index": index, "event_id": event_id, "alert": source},
    )


def _next_cursor(
    items: list[dict[str, JsonValue]], previous: list[JsonValue] | None
) -> list[JsonValue]:
    cursor = items[-1].get("sort")
    if (
        not isinstance(cursor, list)
        or len(cursor) != 4
        or cursor == previous
        or any(not isinstance(part, (str, int, float)) for part in cursor)
    ):
        raise _InvalidResponseError("Missing or repeated pagination cursor")
    return cursor


def _page_complete(
    total: int | None,
    seen_count: int,
    item_count: int,
    page_size: int,
    provider: str,
    gaps: list[str],
) -> bool:
    if total is not None and seen_count > total:
        raise _InvalidResponseError("Provider returned more records than its total")
    if total is not None and seen_count >= total:
        return True
    if item_count < page_size:
        if total is not None:
            gaps.append(f"{provider} page ended before the reported total")
        return True
    return False


def _manager_total(data: dict[str, JsonValue], gaps: list[str]) -> int | None:
    total = data.get("total_affected_items")
    if type(total) is not int or total < 0:
        gaps.append("Manager did not supply a valid total")
        total = None
    if data.get("total_failed_items", 0) or data.get("failed_items"):
        gaps.append("Manager reported failed items")
    return total


class _Reader(ABC):
    def __init__(
        self,
        settings: WazuhManagerSettings | WazuhIndexerSettings,
        client: httpx2.AsyncClient | None,
    ) -> None:
        self.settings: WazuhManagerSettings | WazuhIndexerSettings = settings
        self.client: httpx2.AsyncClient = client or httpx2.AsyncClient(
            verify=settings.verify_tls,
            follow_redirects=False,
            timeout=_TOTAL_TIMEOUT,
            trust_env=False,
        )
        self._owns_client: bool = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()

    def _scope(self, query: ReadQuery, resource: EndpointResource) -> None:
        if (
            resource.org_id != self.settings.org_id
            or query.resource_id != resource.resource_id
        ):
            raise ValueError("Reader organization/resource binding mismatch")

    def _auth(self) -> tuple[str, str]:
        return (
            self.settings.username.get_secret_value(),
            self.settings.password.get_secret_value(),
        )

    async def read(
        self, query: ReadQuery, resource: EndpointResource
    ) -> ReadCollection:
        query = ReadQuery.model_validate(query.model_dump())
        resource = EndpointResource.model_validate(resource.model_dump())
        self._scope(query, resource)
        budget = _WireBudget()
        try:
            async with asyncio.timeout(_TOTAL_TIMEOUT):
                return await self._read(query, resource, budget)
        except TimeoutError:
            return _request_failure(budget, "Provider deadline exceeded")
        except _ByteLimitError:
            return _collection(
                budget.observations, ["Provider body exceeded 64 KiB"], truncated=True
            )
        except httpx2.HTTPStatusError as exc:
            return _request_failure(
                budget, f"Provider HTTP status {exc.response.status_code}"
            )
        except httpx2.HTTPError:
            return _request_failure(budget, "Provider request failed")
        except (ValueError, KeyError, TypeError):
            return ReadCollection(
                status="error",
                gaps=("Invalid provider response; observations discarded",),
            )

    @abstractmethod
    async def _read(
        self, query: ReadQuery, resource: EndpointResource, budget: _WireBudget
    ) -> ReadCollection:
        raise NotImplementedError


class WazuhManagerReader(_Reader):
    """Manager agent context reports connectivity, never service health."""

    def __init__(
        self, settings: WazuhManagerSettings, client: httpx2.AsyncClient | None = None
    ) -> None:
        super().__init__(settings, client)
        self._origin: str = settings.manager_url

    @override
    async def _read(
        self, query: ReadQuery, resource: EndpointResource, budget: _WireBudget
    ) -> ReadCollection:
        if query.event_kind not in {"inventory", "coverage"}:
            return ReadCollection(
                status="unsupported",
                gaps=("Manager supports endpoint inventory and coverage only",),
            )
        async with self.client.stream(
            "POST",
            f"{self._origin}/security/user/authenticate",
            params={"raw": "true"},
            auth=self._auth(),
            follow_redirects=False,
            timeout=_TOTAL_TIMEOUT,
        ) as response:
            token = (await budget.consume(response)).decode().strip()
        if not token or len(token) > 8192 or any(char.isspace() for char in token):
            raise _InvalidResponseError("Invalid manager token")
        observations = budget.observations
        gaps: list[str] = []
        seen: set[str] = set()
        for page in range(query.max_pages):
            async with self.client.stream(
                "GET",
                f"{self._origin}/agents",
                auth=None,
                headers={"Authorization": f"Bearer {token}"},
                params={
                    "agents_list": resource.agent_id,
                    "limit": query.page_size,
                    "offset": page * query.page_size,
                    "sort": "+id",
                },
                follow_redirects=False,
                timeout=_TOTAL_TIMEOUT,
            ) as response:
                payload = _object(_JSON.validate_json(await budget.consume(response)))
            if payload.get("error") != 0:
                raise _InvalidResponseError("Manager returned an error")
            data = _object(payload.get("data"))
            items = _items(data.get("affected_items"), query.page_size)
            total = _manager_total(data, gaps)
            # Validate the whole provider page before retaining or truncating it.
            # A foreign record after a large record must still reject the page.
            page_observations = [
                _manager_observation(item, query, resource, gaps, seen)
                for item in items
            ]
            for observation in page_observations:
                if observation is None:
                    continue
                if not budget.observe(observation):
                    gaps.append("Observation output reached 32 KiB")
                    return _collection(observations, gaps, truncated=True)
            if _page_complete(
                total, len(seen), len(items), query.page_size, "Manager", gaps
            ):
                return _collection(observations, gaps)
        gaps.append("Manager page bound reached")
        return _collection(observations, gaps, truncated=True)


class WazuhIndexerReader(_Reader):
    """Fixed alert/authentication search over the separately bound indexer."""

    def __init__(
        self, settings: WazuhIndexerSettings, client: httpx2.AsyncClient | None = None
    ) -> None:
        super().__init__(settings, client)
        self._origin: str = settings.indexer_url

    @override
    async def _read(
        self, query: ReadQuery, resource: EndpointResource, budget: _WireBudget
    ) -> ReadCollection:
        if query.event_kind not in {"detection", "authentication"}:
            return ReadCollection(
                status="unsupported",
                gaps=("Indexer supports detection and authentication only",),
            )
        filters: list[JsonValue] = [
            {"term": {"agent.id": resource.agent_id}},
            {
                "range": {
                    "timestamp": {
                        "gte": query.start.isoformat(),
                        "lte": query.end.isoformat(),
                    }
                }
            },
        ]
        if query.event_kind == "authentication":
            filters.append(
                {
                    "terms": {
                        "rule.groups": [
                            "authentication_failed",
                            "authentication_success",
                        ]
                    }
                }
            )
        body: dict[str, JsonValue] = {
            "size": query.page_size,
            "track_total_hits": True,
            "query": {"bool": {"filter": filters}},
            # Wazuh's template maps strings to keywords. _id is not sortable;
            # manager/id provide a stable alert identity across manager nodes.
            "sort": [
                {"timestamp": "asc"},
                {"manager.name": "asc"},
                {"id": "asc"},
                {"_index": "asc"},
            ],
        }
        observations = budget.observations
        gaps: list[str] = []
        seen: set[tuple[str, str]] = set()
        previous_cursor: list[JsonValue] | None = None
        expected_total: int | None = None
        for _ in range(query.max_pages):
            async with self.client.stream(
                "POST",
                f"{self._origin}/wazuh-alerts-*/_search",
                json=body,
                auth=self._auth(),
                follow_redirects=False,
                timeout=_TOTAL_TIMEOUT,
            ) as response:
                payload = _object(_JSON.validate_json(await budget.consume(response)))
            count = _indexer_total(payload, gaps)
            if expected_total is not None and count != expected_total:
                gaps.append("Indexer total changed during pagination")
            expected_total = count
            items = _items(_object(payload.get("hits")).get("hits"), query.page_size)
            page_observations = [
                _indexer_observation(item, query, resource, seen) for item in items
            ]
            for observation in page_observations:
                if not budget.observe(observation):
                    gaps.append("Observation output reached 32 KiB")
                    return _collection(observations, gaps, truncated=True)
            if _page_complete(
                count, len(seen), len(items), query.page_size, "Indexer", gaps
            ):
                return _collection(observations, gaps)
            cursor = _next_cursor(items, previous_cursor)
            previous_cursor = cursor
            body["search_after"] = cursor
        gaps.append("Indexer page bound reached")
        return _collection(observations, gaps, truncated=True)
