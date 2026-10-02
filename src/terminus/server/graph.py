"""Tenant-scoped graph and source-evidence endpoints."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from terminus.core.ids import OrgId
from terminus.investigation.graph import GraphEventStore
from terminus.server.deps import get_current_org

graph_router = APIRouter(prefix="/investigation/graph", tags=["Investigation Graph"])


def _window(from_time: str | None, until: str | None) -> tuple[str, str]:
    now = datetime.now(UTC)
    try:
        end = datetime.fromisoformat(until) if until else now
        start = datetime.fromisoformat(from_time) if from_time else end - timedelta(days=7)
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("Timezone required")
        start, end = start.astimezone(UTC), end.astimezone(UTC)
    except ValueError as exc:
        raise HTTPException(422, "Use ISO 8601 timestamps with timezones") from exc
    if start > end or end - start > timedelta(days=7) or end > now + timedelta(minutes=5):
        raise HTTPException(422, "Graph window must be at most seven days and cannot end in the future")
    return start.isoformat(), end.isoformat()


@graph_router.get("")
def graph_snapshot(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    from_time: Annotated[str | None, Query(alias="from")] = None,
    until: str | None = None,
    policy: Literal["all", "ignore", "triage", "escalate"] = "all",
) -> dict:
    start, end = _window(from_time, until)
    return GraphEventStore().snapshot(org_id, start, end, policy)


@graph_router.get("/evidence")
def graph_evidence(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    from_time: Annotated[str | None, Query(alias="from")] = None,
    until: str | None = None,
    source_ip: str | None = None,
    host: str | None = None,
    mitre: str | None = None,
    alert_id: str | None = None,
    policy: Literal["all", "ignore", "triage", "escalate"] = "all",
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    if source_ip is None and host is None and mitre is None and alert_id is None:
        raise HTTPException(422, "Select a graph node or connection to inspect evidence")
    start, end = _window(from_time, until)
    return GraphEventStore().evidence(org_id, start, end, source_ip=source_ip, host=host, mitre=mitre, alert_id=alert_id, policy=policy, limit=limit, offset=offset)


@graph_router.get("/network")
def graph_network(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    from_time: Annotated[str | None, Query(alias="from")] = None,
    until: str | None = None,
    policy: Literal["all", "ignore", "triage", "escalate"] = "all",
) -> dict:
    start, end = _window(from_time, until)
    return GraphEventStore().network(org_id, start, end, policy)
