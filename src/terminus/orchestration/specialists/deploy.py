"""Scheduler-loadable specialist handlers: ``ROLE=...specialists.deploy:ROLE``.

Configuration is explicit and read lazily on the first leased task:

* ``TERMINUS_SPECIALIST_DATABASE``: SQLite path (the same file the scheduler uses).
* ``TERMINUS_SPECIALIST_ACTOR_USER_ID``: service-account user whose live
  organization membership authorizes reads (it must be an operator member).

If either is missing the handler raises ``SpecialistDeploymentError`` so the run
fails with a clear message; it never fabricates a result. No model transport is
configured, so runs are ``tools_only``.

Connector credentials: the repository has no production wiring for per-org Wazuh
manager/indexer credentials, so none is invented here. By default an
organization that exists in the database gets a store-only read service (incident
and evidence tools; every connector-backed tool surfaces an explicit gap), and
unknown organizations resolve to nothing (a ``service_not_configured`` gap).
Deployments inject real readers with ``configure_connectors``, a callable
returning ``(manager, indexer)`` readers for an organization; each reader's
settings must name that organization, which ``InvestigationReadService`` checks.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from datetime import datetime

from pydantic import JsonValue

from terminus.orchestration.scheduler import JobContext, JobHandler
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.specialists.factory import build_specialist_handlers
from terminus.orchestration.specialists.runtime import SpecialistDeps
from terminus.storage.db import Database
from terminus.toolkit.context import ToolReadPolicyStore
from terminus.toolkit.readers import InvestigationReadService
from terminus.toolkit.wazuh_readers import WazuhIndexerReader, WazuhManagerReader

DATABASE_ENV = "TERMINUS_SPECIALIST_DATABASE"
ACTOR_ENV = "TERMINUS_SPECIALIST_ACTOR_USER_ID"

ConnectorFactory = Callable[
    [str], tuple[WazuhManagerReader | None, WazuhIndexerReader | None]
]

_LOCK = threading.Lock()
_STATE: dict[str, object] = {}
_CONNECTORS: list[ConnectorFactory] = []


class SpecialistDeploymentError(RuntimeError):
    """Required specialist deployment configuration is missing or invalid."""


def configure_connectors(factory: ConnectorFactory | None) -> None:
    """Inject trusted per-org readers (None restores store-only services)."""
    with _LOCK:
        _CONNECTORS[:] = [] if factory is None else [factory]
        _ = _STATE.pop("handlers", None)


def reset_deployment() -> None:
    """Drop the cached deployment (tests and reconfiguration)."""
    with _LOCK:
        _STATE.clear()


def build_deployment_deps(
    environ: Mapping[str, str], *, clock: Callable[[], datetime] | None = None
) -> SpecialistDeps:
    """Validate explicit configuration and build the shared specialist deps."""
    path = environ.get(DATABASE_ENV, "").strip()
    actor = environ.get(ACTOR_ENV, "").strip()
    missing = [
        name for name, value in ((DATABASE_ENV, path), (ACTOR_ENV, actor)) if not value
    ]
    if missing:
        raise SpecialistDeploymentError(
            "Specialist deployment is not configured; set " + ", ".join(missing)
        )
    db = Database(path)
    scheduler = SchedulerStore(db) if clock is None else SchedulerStore(db, clock=clock)
    policies = ToolReadPolicyStore(db)
    services: dict[str, InvestigationReadService] = {}
    guard = threading.Lock()

    def read_service_for(org_id: str) -> InvestigationReadService | None:
        with guard:
            if org_id in services:
                return services[org_id]
            if not db.fetchone("SELECT 1 FROM organizations WHERE org_id=?", (org_id,)):
                return None  # unknown organization fails closed
            manager, indexer = _CONNECTORS[0](org_id) if _CONNECTORS else (None, None)
            service = InvestigationReadService(
                org_id, scheduler, policies, manager=manager, indexer=indexer
            )
            services[org_id] = service
            return service

    return SpecialistDeps(read_service_for=read_service_for, actor_user_id=actor)


def _handlers() -> dict[str, JobHandler]:
    with _LOCK:
        cached = _STATE.get("handlers")
        if cached is None:
            cached = build_specialist_handlers(build_deployment_deps(os.environ))
            _STATE["handlers"] = cached
        return cached  # pyright: ignore[reportReturnType]


async def _run(role: str, ctx: JobContext) -> JsonValue:
    return await _handlers()[role](ctx)


async def triage(ctx: JobContext) -> JsonValue:
    return await _run("triage", ctx)


async def identity(ctx: JobContext) -> JsonValue:
    return await _run("identity", ctx)


async def endpoint(ctx: JobContext) -> JsonValue:
    return await _run("endpoint", ctx)


async def network(ctx: JobContext) -> JsonValue:
    return await _run("network", ctx)


async def response_planner(ctx: JobContext) -> JsonValue:
    return await _run("response_planner", ctx)


async def verification(ctx: JobContext) -> JsonValue:
    return await _run("verification", ctx)


async def evidence_reporting(ctx: JobContext) -> JsonValue:
    return await _run("evidence_reporting", ctx)


async def application_api(ctx: JobContext) -> JsonValue:
    return await _run("application_api", ctx)
