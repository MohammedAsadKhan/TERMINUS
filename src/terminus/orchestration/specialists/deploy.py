"""Scheduler-loadable specialist handlers: ``ROLE=...specialists.deploy:ROLE``.

Configuration is explicit and read lazily on the first leased task:

* ``TERMINUS_SPECIALIST_DATABASE``: SQLite path (the same file the scheduler uses).
* ``TERMINUS_SPECIALIST_ACTOR_USER_ID``: service-account user whose live
  organization membership authorizes reads (it must be an operator member).

If either is missing the handler raises ``SpecialistDeploymentError`` so the run
fails with a clear message (non-retryable, so it does not consume retries); it
never fabricates a result. Model transport remains disabled unless
``TERMINUS_SPECIALIST_LIVE_MODELS`` is explicitly ``true``. Enabled runs use
registered connections, durable role policy, the shared budget ledger, and the
configured credential cipher.

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

import json
import os
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import cast

from pydantic import JsonValue, TypeAdapter

from terminus.model_gateway.models import ModelConnectionView
from terminus.model_gateway.routing import ClientFactory, ModelRoutingService
from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.scheduler import JobContext, JobHandler
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.specialists.factory import build_specialist_handlers
from terminus.orchestration.specialists.runtime import SharedHelpContext, SpecialistDeps
from terminus.storage.db import Database
from terminus.toolkit.context import ToolReadPolicyStore
from terminus.toolkit.readers import InvestigationReadService
from terminus.toolkit.wazuh_readers import WazuhIndexerReader, WazuhManagerReader

DATABASE_ENV = "TERMINUS_SPECIALIST_DATABASE"
ACTOR_ENV = "TERMINUS_SPECIALIST_ACTOR_USER_ID"
LIVE_MODELS_ENV = "TERMINUS_SPECIALIST_LIVE_MODELS"
MODEL_CREDENTIALS_ENV = "TERMINUS_MODEL_CREDENTIALS_KEY"

ConnectorFactory = Callable[
    [str], tuple[WazuhManagerReader | None, WazuhIndexerReader | None]
]

_LOCK = threading.Lock()
_STATE: dict[str, object] = {}
_CONNECTORS: list[ConnectorFactory] = []
_STRING_LIST = TypeAdapter(list[str])


class SpecialistDeploymentError(RuntimeError):
    """Required specialist deployment configuration is missing or invalid.

    ``retryable`` is False: the scheduler records a terminal failure instead of
    consuming retry attempts, because retrying cannot fix missing configuration.
    """

    retryable: bool = False


def configure_connectors(factory: ConnectorFactory | None) -> None:
    """Inject trusted per-org readers (None restores store-only services)."""
    with _LOCK:
        _CONNECTORS[:] = [] if factory is None else [factory]
        _ = _STATE.pop("handlers", None)


def reset_deployment() -> None:
    """Drop the cached deployment (tests and reconfiguration)."""
    with _LOCK:
        _STATE.clear()


def build_deployment_deps(  # noqa: C901, PLR0915 - explicit composition root
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
    coordination = CoordinationService(db)
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

    def incident_time_for(org_id: str, incident_id: str) -> datetime | None:
        """Source timestamp of the durable incident record (same field incident.get reads)."""
        row = db.fetchone(
            "SELECT raw_payload_json FROM incidents WHERE org_id=? AND ticket_id=?",
            (org_id, incident_id),
        )
        if row is None:
            return None
        try:
            payload = cast("dict[str, object]", json.loads(str(cast("object", row["raw_payload_json"]))))
            stamp = datetime.fromisoformat(str(payload["timestamp"]))
        except (ValueError, TypeError, KeyError):
            return None
        return stamp if stamp.tzinfo is not None else stamp.replace(tzinfo=UTC)

    def help_context_for(org_id: str, task_id: str) -> SharedHelpContext | None:
        from terminus.orchestration.storage import OrchestrationNotFoundError

        try:
            payload = coordination.get_help_context(org_id, task_id)
        except OrchestrationNotFoundError:
            return None
        try:
            evidence = _STRING_LIST.validate_python(payload.get("shared_evidence_ids"))
            expected = _STRING_LIST.validate_python(
                payload.get("expected_evidence_kinds")
            )
        except ValueError:
            raise SpecialistDeploymentError(
                "Invalid durable help evidence contract"
            ) from None
        help_id = payload.get("help_request_id")
        objective = payload.get("objective")
        if not isinstance(help_id, str) or not isinstance(objective, str):
            raise SpecialistDeploymentError("Invalid durable help request contract")
        return SharedHelpContext(
            help_request_id=help_id,
            objective=objective,
            expected_evidence_kinds=tuple(expected),
            shared_evidence_ids=tuple(evidence),
        )

    routing: ModelRoutingService | None = None
    client_for: ClientFactory | None = None
    live_setting = environ.get(LIVE_MODELS_ENV, "").strip().casefold()
    if live_setting not in {"", "false", "true"}:
        raise SpecialistDeploymentError(
            f"{LIVE_MODELS_ENV} must be true or false"
        )
    if live_setting == "true":
        from terminus.model_gateway.admission import ModelAdmissionService
        from terminus.model_gateway.ledger import ModelBudgetStore
        from terminus.model_gateway.live import (
            ProductionModelTransport,
            resolve_addresses,
        )
        from terminus.model_gateway.policy import ModelPolicyStore
        from terminus.model_gateway.safety import EndpointVerifier
        from terminus.model_gateway.secrets import CredentialCipher
        from terminus.model_gateway.store import ModelConnectionStore

        key = environ.get(MODEL_CREDENTIALS_ENV, "").strip()
        if not key:
            raise SpecialistDeploymentError(
                f"Live specialist models require {MODEL_CREDENTIALS_ENV}"
            )
        try:
            connections = ModelConnectionStore(
                db, CredentialCipher.from_key(key)
            )
        except Exception:
            raise SpecialistDeploymentError(
                "Live specialist model credential storage is unavailable"
            ) from None
        admission = ModelAdmissionService(
            scheduler,
            ModelPolicyStore(db),
            connections,
            EndpointVerifier(resolve_addresses),
        )
        routing = ModelRoutingService(admission, ModelBudgetStore(db, clock=clock))

        def live_client_for(
            connection: ModelConnectionView,
        ) -> ProductionModelTransport:
            return ProductionModelTransport(connection, connections, actor)

        client_for = live_client_for

    return SpecialistDeps(
        read_service_for=read_service_for,
        actor_user_id=actor,
        routing=routing,
        client_for=client_for,
        incident_time_for=incident_time_for,
        help_context_for=help_context_for,
    )


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
