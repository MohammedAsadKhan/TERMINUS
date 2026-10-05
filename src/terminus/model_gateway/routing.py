"""Capability routing and bounded approved fallback over M03 admission.

Candidates come only from exact policy grants (role, area, connection version,
model). Every attempt is independently admitted; no path substitutes scripted
findings, and fallback never widens a grant. Every attempt also needs financial
admission: an org-wide reservation is committed before any provider I/O and is
settled, left ambiguous, or released only when I/O provably never started.
Fixture execution and explicitly configured gated production transports.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar, Final, Literal, NoReturn
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from terminus.model_gateway.admission import (
    ModelAdmissionDeniedError,
    ModelAdmissionService,
)
from terminus.model_gateway.contracts import ModelResponse
from terminus.model_gateway.fixture_client import FixtureModelClient
from terminus.model_gateway.ledger import (
    ModelBudgetStore,
    ModelReservation,
    ReservationRequest,
    UsageReport,
)
from terminus.model_gateway.live import ProductionModelTransport
from terminus.model_gateway.models import ModelConnectionView, Provider
from terminus.orchestration.scheduler_models import JobLease
from terminus.toolkit.catalog import CORE_ROLES

Capability = Literal["structured_output", "native_schema", "tool_calls"]

# Codec facts (compatible.py/native.py): DeepSeek uses json_object mode and the
# schema is enforced by local validation rather than provider-native schemas.
_BASE: Final[frozenset[Capability]] = frozenset({"structured_output", "tool_calls"})
_NATIVE: Final[frozenset[Capability]] = frozenset({"native_schema"})
DEFAULT_CAPABILITIES: Final[frozenset[Capability]] = frozenset({"structured_output"})
PROVIDER_CAPABILITIES: Final[dict[Provider, frozenset[Capability]]] = {
    "openai": _BASE | _NATIVE,
    "anthropic": _BASE | _NATIVE,
    "gemini": _BASE | _NATIVE,
    "openrouter": _BASE | _NATIVE,
    "openai_compatible": _BASE | _NATIVE,
    "local": _BASE | _NATIVE,
    "deepseek": _BASE,
}
# M03 admits a first structured turn only; tool declarations and continuations
# need their own admission, so tool routing is excluded rather than assumed.
ADMITTED_CAPABILITIES: Final[frozenset[Capability]] = frozenset(
    {"structured_output", "native_schema"}
)
ROUTABLE_ROLES: Final[frozenset[str]] = CORE_ROLES | {
    "main_orchestrator",
    "area_orchestrator",
}
# Terminal-looking provider failures that justify trying another approved
# route. Refusals, truncation and successful output never trigger fallback.
FALLBACK_ERRORS: Final[frozenset[str]] = frozenset(
    {
        "rate_limited",
        "provider_unavailable",
        "timeout_unknown_usage",
        "transport_unknown_usage",
        "authentication_denied",
        "unsupported_request",
        "invalid_provider_contract",
        "response_too_large",
    }
)
MAX_ATTEMPTS: Final = 3

ClientFactory = Callable[
    [ModelConnectionView], FixtureModelClient | ProductionModelTransport | None
]


class ModelRoutingDeniedError(ValueError):
    """No approved route; safe text without prompts, evidence or endpoints."""


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True
    )


class RouteRef(_Contract):
    connection_id: str = Field(min_length=1, max_length=200)
    model: str = Field(min_length=1, max_length=128)


class RouteExclusion(_Contract):
    connection_id: str
    model: str
    reason: str


class RouteAttempt(_Contract):
    attempt: int
    connection_id: str
    connection_version: int
    provider: str
    model: str
    policy_version: int
    rationale: str
    outcome: str
    admission_id: str
    request_digest: str
    reservation_id: str
    cost_known: bool
    cost_micro_usd: int | None
    usage_known: bool


class RoutedModelResult(_Contract):
    """Provenance is the final attempt; `response` is exactly its outcome."""

    route_id: str
    response: ModelResponse
    attempts: tuple[RouteAttempt, ...] = Field(min_length=1)
    excluded: tuple[RouteExclusion, ...]
    exhausted: bool

    @property
    def selected(self) -> RouteAttempt:
        return self.attempts[-1]


@dataclass(frozen=True)
class _Candidate:
    connection: ModelConnectionView
    model: str


def _safe_code(code: str | None) -> str:
    if code is None:
        return "none"
    return code if code in FALLBACK_ERRORS else "unclassified"


class ModelRoutingService:
    """Routing and audit only; admission owns authorization of every attempt."""

    def __init__(
        self, admission: ModelAdmissionService, budgets: ModelBudgetStore
    ) -> None:
        if admission.scheduler.db is not budgets.db:
            raise ModelRoutingDeniedError("Model services require one database")
        self.admission: ModelAdmissionService = admission
        self.budgets: ModelBudgetStore = budgets
        db = admission.scheduler.db
        with db.transaction() as conn:
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS model_routing_audit (
                audit_id TEXT PRIMARY KEY, route_id TEXT NOT NULL,
                seq INTEGER NOT NULL, org_id TEXT NOT NULL,
                incident_id TEXT NOT NULL, task_id TEXT NOT NULL,
                run_id TEXT NOT NULL, kind TEXT NOT NULL,
                connection_id TEXT, connection_version INTEGER,
                provider TEXT, model TEXT, policy_version INTEGER,
                rationale TEXT, outcome TEXT NOT NULL,
                admission_id TEXT, request_digest TEXT,
                required_capabilities TEXT NOT NULL, created_at TEXT NOT NULL,
                reservation_id TEXT
            )""")
            info = conn.execute("PRAGMA table_info(model_routing_audit)").fetchall()
            if "reservation_id" not in {str(row[1]) for row in info}:  # pyright: ignore[reportAny]
                _ = conn.execute(
                    "ALTER TABLE model_routing_audit ADD COLUMN reservation_id TEXT"
                )
            _ = conn.execute("""CREATE TRIGGER IF NOT EXISTS model_routing_audit_no_update
                BEFORE UPDATE ON model_routing_audit BEGIN
                SELECT RAISE(ABORT, 'model routing audit is immutable'); END""")
            _ = conn.execute("""CREATE TRIGGER IF NOT EXISTS model_routing_audit_no_delete
                BEFORE DELETE ON model_routing_audit BEGIN
                SELECT RAISE(ABORT, 'model routing audit is immutable'); END""")

    def _log(
        self,
        ctx: _RouteContext,
        kind: str,
        outcome: str,
        *,
        candidate: _Candidate | None = None,
        connection_id: str | None = None,
        model: str | None = None,
        rationale: str | None = None,
        admission_id: str | None = None,
        request_digest: str | None = None,
        reservation_id: str | None = None,
    ) -> None:
        ctx.seq += 1
        connection = candidate.connection if candidate else None
        db = self.admission.scheduler.db
        _ = db.execute(
            """INSERT INTO model_routing_audit
               (audit_id, route_id, seq, org_id, incident_id, task_id, run_id,
                kind, connection_id, connection_version, provider, model,
                policy_version, rationale, outcome, admission_id, request_digest,
                required_capabilities, created_at, reservation_id)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid4()),
                ctx.route_id,
                ctx.seq,
                ctx.org_id,
                ctx.incident_id,
                ctx.task_id,
                ctx.run_id,
                kind,
                connection.connection_id if connection else connection_id,
                connection.version if connection else None,
                connection.provider if connection else None,
                candidate.model if candidate else model,
                ctx.policy_version,
                rationale,
                outcome,
                admission_id,
                request_digest,
                ",".join(sorted(ctx.required)),
                self.admission.scheduler.clock().isoformat(),
                reservation_id,
            ),
        )

    def _owned(self, lease: JobLease, actor: str) -> None:
        # Stale ownership or cancellation ends routing; it is never a fallback.
        try:
            _ = self.admission.task_for(lease, actor)
        except ModelAdmissionDeniedError:
            raise ModelRoutingDeniedError("Model ownership is stale") from None

    def _candidates(
        self, ctx: _RouteContext, grants_for: list[tuple[str, int, tuple[str, ...]]]
    ) -> tuple[list[_Candidate], list[RouteExclusion]]:
        eligible: list[_Candidate] = []
        excluded: list[RouteExclusion] = []
        seen: set[tuple[str, str]] = set()
        for connection_id, version, models in grants_for:
            try:
                connection = self.admission.connections.get(
                    ctx.org_id, ctx.actor, connection_id
                )
            except Exception:
                connection = None
            for model in models:
                if (connection_id, model) in seen:
                    continue
                seen.add((connection_id, model))
                reason: str | None = None
                if connection is None or not connection.enabled:
                    reason = "connection_unavailable"
                elif connection.version != version:
                    reason = "connection_version_mismatch"
                elif model not in connection.models:
                    reason = "model_unavailable"
                elif not (
                    ctx.required <= PROVIDER_CAPABILITIES[connection.provider]
                    and ctx.required <= ADMITTED_CAPABILITIES
                ):
                    reason = (
                        "capability_not_admitted"
                        if ctx.required - ADMITTED_CAPABILITIES
                        else "unsupported_capability"
                    )
                if reason is not None or connection is None:
                    excluded.append(
                        RouteExclusion(
                            connection_id=connection_id,
                            model=model,
                            reason=reason or "connection_unavailable",
                        )
                    )
                else:
                    eligible.append(_Candidate(connection, model))
        return eligible, excluded

    async def route_fixture(  # noqa: C901, PLR0912, PLR0915
        self,
        lease: JobLease,
        actor_user_id: str,
        evidence_ids: tuple[str, ...],
        client_for: ClientFactory,
        *,
        capabilities: frozenset[Capability] = DEFAULT_CAPABILITIES,
        preferred: RouteRef | None = None,
        max_attempts: int = 1,
        output_schema: dict[str, JsonValue] | None = None,
        max_output_tokens: int = 1024,
    ) -> RoutedModelResult:
        """Route one task turn; fallback needs max_attempts > 1 and stays in-grant."""
        if (
            type(max_attempts) is not int
            or not 1 <= max_attempts <= MAX_ATTEMPTS
            or type(capabilities) is not frozenset
            or not capabilities
        ):
            raise ModelRoutingDeniedError("Invalid routing request")
        try:
            task = self.admission.task_for(lease, actor_user_id)
            policy = self.admission.policies.get(task.org_id, actor_user_id)
        except (ModelAdmissionDeniedError, LookupError, PermissionError, ValueError):
            raise ModelRoutingDeniedError("Model routing denied") from None
        ctx = _RouteContext(
            route_id=str(uuid4()),
            org_id=task.org_id,
            incident_id=task.incident_id,
            task_id=task.task_id,
            run_id=lease.run_id,
            actor=actor_user_id,
            policy_version=policy.version,
            required=capabilities,
        )
        area = task.area if task.role == "area_orchestrator" else None
        if task.role not in ROUTABLE_ROLES or not policy.enabled:
            self._deny(ctx, "role_or_policy_unavailable")
        grants = [
            (grant.connection_id, grant.connection_version, grant.models)
            for grant in policy.grants
            if grant.role == task.role and grant.area == area
        ]
        eligible, excluded = self._candidates(ctx, grants)
        for item in excluded:
            self._log(
                ctx,
                "excluded",
                item.reason,
                connection_id=item.connection_id,
                model=item.model,
            )
        if preferred is not None:
            match = [
                c
                for c in eligible
                if (c.connection.connection_id, c.model)
                == (preferred.connection_id, preferred.model)
            ]
            if not match:
                self._deny(ctx, "preferred_route_ineligible")
            eligible = match + [c for c in eligible if c is not match[0]]
        attempts: list[RouteAttempt] = []
        response: ModelResponse | None = None
        rationale = "preferred_request" if preferred is not None else "policy_order"
        for candidate in eligible:
            if len(attempts) >= max_attempts:
                break
            self._owned_logged(ctx, lease, actor_user_id)
            client = client_for(candidate.connection)
            if client is None:
                item = RouteExclusion(
                    connection_id=candidate.connection.connection_id,
                    model=candidate.model,
                    reason="transport_unavailable",
                )
                excluded.append(item)
                self._log(ctx, "excluded", item.reason, candidate=candidate)
                continue
            try:
                call = await self.admission.prepare(
                    lease,
                    actor_user_id,
                    candidate.connection.connection_id,
                    candidate.model,
                    evidence_ids,
                    output_schema=output_schema,
                    max_output_tokens=max_output_tokens,
                )
            except ModelAdmissionDeniedError:
                self._owned_logged(ctx, lease, actor_user_id)
                item = RouteExclusion(
                    connection_id=candidate.connection.connection_id,
                    model=candidate.model,
                    reason="admission_denied",
                )
                excluded.append(item)
                self._log(ctx, "excluded", item.reason, candidate=candidate)
                continue
            try:
                reservation = self.budgets.reserve(
                    ctx.org_id,
                    actor_user_id,
                    ReservationRequest(
                        idempotency_key=(
                            f"{ctx.route_id}:{len(attempts) + 1}:{call.admission_id}"
                        ),
                        incident_id=call.incident_id,
                        task_id=call.task_id,
                        run_id=call.run_id,
                        connection_id=candidate.connection.connection_id,
                        connection_version=candidate.connection.version,
                        model=candidate.model,
                        request_bytes=len(call.request.model_dump_json().encode()),
                        max_output_tokens=call.request.max_output_tokens,
                        max_input_tokens=65536
                        if type(client) is ProductionModelTransport
                        else None,
                    ),
                )
            except (ValueError, LookupError):
                # No provider I/O; the unused admission binding is never invoked.
                item = RouteExclusion(
                    connection_id=candidate.connection.connection_id,
                    model=candidate.model,
                    reason="budget_denied",
                )
                excluded.append(item)
                self._log(
                    ctx,
                    "excluded",
                    item.reason,
                    candidate=candidate,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                )
                continue
            rid = reservation.reservation_id
            try:
                self._log(
                    ctx,
                    "attempt_started",
                    "admitted",
                    candidate=candidate,
                    rationale=rationale,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                    reservation_id=rid,
                )
            except BaseException:
                # Provider I/O provably never started.
                self._ledger_safely(self.budgets.release, ctx.org_id, rid)
                raise
            try:
                response = (
                    await self.admission.respond_live(call, client, reservation_id=rid)
                    if type(client) is ProductionModelTransport
                    else await self.admission.respond_fixture(call, client)
                )
            except asyncio.CancelledError:
                self._ledger_safely(self.budgets.mark_ambiguous, ctx.org_id, rid)
                self._log(
                    ctx,
                    "attempt_cancelled",
                    "cancelled_unknown",
                    candidate=candidate,
                    rationale=rationale,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                    reservation_id=rid,
                )
                raise
            except ModelAdmissionDeniedError:
                self._ledger_safely(self.budgets.mark_ambiguous, ctx.org_id, rid)
                self._log(
                    ctx,
                    "attempt_denied",
                    "denied_unknown",
                    candidate=candidate,
                    rationale=rationale,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                    reservation_id=rid,
                )
                raise ModelRoutingDeniedError("Model attempt denied") from None
            except BaseException:
                self._ledger_safely(self.budgets.mark_ambiguous, ctx.org_id, rid)
                self._ledger_safely(
                    self._log,
                    ctx,
                    "attempt_failed",
                    "failed_unknown",
                    candidate=candidate,
                    rationale=rationale,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                    reservation_id=rid,
                )
                raise
            settled = self._settle(ctx.org_id, rid, response)
            outcome = (
                f"error:{_safe_code(response.error_code)}"
                if response.status == "error"
                else response.status
            )
            cost = (
                settled.actual_cost_micro_usd
                if settled.state in ("settled", "reconciled")
                else None
            )
            attempts.append(
                RouteAttempt(
                    attempt=len(attempts) + 1,
                    connection_id=candidate.connection.connection_id,
                    connection_version=candidate.connection.version,
                    provider=candidate.connection.provider,
                    model=candidate.model,
                    policy_version=policy.version,
                    rationale=rationale,
                    outcome=outcome,
                    admission_id=call.admission_id,
                    request_digest=call.request_digest,
                    reservation_id=rid,
                    cost_known=cost is not None,
                    cost_micro_usd=cost,
                    usage_known=response.status != "error"
                    and response.usage.input_tokens is not None
                    and response.usage.output_tokens is not None,
                )
            )
            self._log(
                ctx,
                "attempt_finished",
                outcome,
                candidate=candidate,
                rationale=rationale,
                admission_id=call.admission_id,
                request_digest=call.request_digest,
                reservation_id=rid,
            )
            if response.status != "error" or response.error_code not in FALLBACK_ERRORS:
                break
            rationale = f"fallback:{_safe_code(response.error_code)}"
        if response is None or not attempts:
            self._deny(ctx, "no_eligible_route")
        return RoutedModelResult(
            route_id=ctx.route_id,
            response=response,
            attempts=tuple(attempts),
            excluded=tuple(excluded),
            exhausted=response.status == "error",
        )

    @staticmethod
    def _ledger_safely(
        action: Callable[..., object], *args: object, **kwargs: object
    ) -> None:
        """Best-effort conservative ledger/audit write that never masks the cause."""
        with contextlib.suppress(Exception):
            _ = action(*args, **kwargs)

    def _settle(
        self, org_id: str, reservation_id: str, response: ModelResponse
    ) -> ModelReservation:
        """Settle known usage; every error and unknown usage stays ambiguous."""
        usage = response.usage
        report = (
            UsageReport()
            if response.status == "error"
            else UsageReport(
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cached_input_tokens=usage.cached_input_tokens,
                reasoning_tokens=usage.reasoning_tokens,
            )
        )
        try:
            return self.budgets.settle(org_id, reservation_id, report)
        except Exception:
            # Keep the reserve counted rather than lose track of spend.
            return self.budgets.mark_ambiguous(
                org_id, reservation_id, reason_code="settle_failed"
            )

    def _owned_logged(self, ctx: _RouteContext, lease: JobLease, actor: str) -> None:
        try:
            self._owned(lease, actor)
        except ModelRoutingDeniedError:
            self._log(ctx, "denied", "ownership_stale")
            raise

    def _deny(self, ctx: _RouteContext, reason: str) -> NoReturn:
        self._log(ctx, "denied", reason)
        raise ModelRoutingDeniedError("No approved model route")


@dataclass
class _RouteContext:
    route_id: str
    org_id: str
    incident_id: str
    task_id: str
    run_id: str
    actor: str
    policy_version: int
    required: frozenset[Capability]
    seq: int = 0
