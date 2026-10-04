"""M06: model evaluation on incident cases with honest live vs contract coverage.

Every (connection, model, case) pair gets one immutable record per track:

* ``contract`` track: the case runs through the real routing, admission and
  budget path with a recorded provider-shaped fixture response encoded for that
  provider's codec. A pass is ``contract_verified`` and is never countable as
  live evidence.
* ``live`` track: ``live_verified`` is reachable only when the caller supplies a
  genuine ``LiveModelTransport`` (not a ``FixtureModelClient``). Nothing in the
  repository provides one and credentials are never resolved here, so by default
  the live track records ``credentials_missing`` or ``transport_unavailable``.

Records are append-only and secret-free: no prompts, evidence text, endpoints or
credentials are stored, failure reasons are short sanitized codes, and unknown
cost is stored as NULL, never zero.
"""

# pyright: reportAny=false

from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import (
    Annotated,
    ClassVar,
    Final,
    Literal,
    Protocol,
    cast,
    runtime_checkable,
)
from uuid import uuid4

import httpx2
from pydantic import BaseModel, ConfigDict, Field, JsonValue

from terminus.model_gateway.contracts import ModelRequest, ModelResponse
from terminus.model_gateway.fixture_client import FixtureModelClient
from terminus.model_gateway.ledger import ReservationRequest, UsageReport
from terminus.model_gateway.models import ModelConnectionView
from terminus.model_gateway.routing import (
    ADMITTED_CAPABILITIES,
    DEFAULT_CAPABILITIES,
    PROVIDER_CAPABILITIES,
    Capability,
    ModelRoutingDeniedError,
    ModelRoutingService,
    RouteRef,
)
from terminus.orchestration.scheduler_models import JobLease
from terminus.storage.db import Database

CoverageState = Literal[
    "contract_verified",
    "contract_failed",
    "live_verified",
    "credentials_missing",
    "transport_unavailable",
    "capability_unsupported",
    "policy_denied",
    "not_configured",
]
Track = Literal["contract", "live"]
COVERAGE_STATES: Final[tuple[str, ...]] = (
    "contract_verified",
    "contract_failed",
    "live_verified",
    "credentials_missing",
    "transport_unavailable",
    "capability_unsupported",
    "policy_denied",
    "not_configured",
)
MAX_REASONS: Final = 8
MAX_REASON_LENGTH: Final = 120
_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 _.:/\[\](),=\-]")
_SECRETISH = re.compile(
    r"(?i)(?:sk-[a-z0-9_-]{6,}|aiza[a-z0-9_-]{6,}|bearer\s+\S+|"  # noqa: ISC003
    + r"(?:api[ _-]?key|token|password|secret)[ _:=/-]*\S+)"
)


class EvaluationCaseLike(Protocol):
    """Structural view of ``evaluation_cases.EvaluationCase`` (only what is used)."""

    @property
    def case_id(self) -> str: ...
    @property
    def role(self) -> str: ...
    @property
    def output_schema(self) -> dict[str, JsonValue]: ...
    @property
    def required_capabilities(self) -> frozenset[str]: ...
    def validate_output(self, output: dict[str, JsonValue]) -> tuple[str, ...]: ...
    def reference_output(self) -> dict[str, JsonValue]: ...


@runtime_checkable
class LiveModelTransport(Protocol):
    """A genuine, non-fixture provider transport. Nothing in the repo implements it."""

    is_live_transport: bool

    async def respond(self, request: ModelRequest) -> ModelResponse: ...


@dataclass(frozen=True)
class EvaluationTask:
    """Scheduler-owned lease and canonical evidence ids for one case."""

    lease: JobLease
    evidence_ids: tuple[str, ...]


TaskProvider = Callable[[EvaluationCaseLike], EvaluationTask | None]
FixtureOutput = Callable[
    [EvaluationCaseLike, ModelConnectionView], dict[str, JsonValue]
]
LiveTransportFactory = Callable[[ModelConnectionView], LiveModelTransport | None]


class EvaluationDeniedError(PermissionError):
    """Caller is not authorized for this organization's evaluations."""


class EvaluationValidationError(ValueError):
    """Invalid evaluation request."""


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True
    )


class EvaluationRecord(_Contract):
    record_id: str
    run_id: str
    org_id: str
    actor_user_id: str
    connection_id: str
    connection_version: int
    provider: str
    model: str
    case_id: str
    role: str
    track: Track
    state: CoverageState
    fixture_only: bool
    failure_reasons: tuple[str, ...]
    cost_known: bool
    cost_micro_usd: int | None
    reservation_id: str | None
    policy_version: int
    started_at: str
    finished_at: str


Count = Annotated[int, Field(ge=0)]


class PairCoverage(_Contract):
    connection_id: str
    connection_version: int
    provider: str
    model: str
    counts: dict[str, Count]
    contract_counts: dict[str, Count]
    live_counts: dict[str, Count]
    contract_verified_count: Count
    live_verified_count: Count
    unknown_cost_count: Count
    last_run_id: str


class CoverageSummary(_Contract):
    org_id: str
    pairs: tuple[PairCoverage, ...]
    live_verified_count: Count
    contract_verified_count: Count
    demo_model: RouteRef | None
    demo_required_case_ids: tuple[str, ...]
    demo_missing_live_case_ids: tuple[str, ...]
    demo_ready: bool
    note: str


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS model_evaluation_records (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT NOT NULL UNIQUE CHECK(length(record_id) <= 36),
        run_id TEXT NOT NULL CHECK(length(run_id) <= 36),
        org_id TEXT NOT NULL CHECK(length(org_id) BETWEEN 1 AND 200),
        actor_user_id TEXT NOT NULL CHECK(length(actor_user_id) <= 200),
        connection_id TEXT NOT NULL CHECK(length(connection_id) BETWEEN 1 AND 200),
        connection_version INTEGER NOT NULL CHECK(connection_version >= 1),
        provider TEXT NOT NULL CHECK(length(provider) <= 40),
        model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
        case_id TEXT NOT NULL CHECK(length(case_id) BETWEEN 1 AND 200),
        role TEXT NOT NULL CHECK(length(role) <= 100),
        track TEXT NOT NULL CHECK(track IN ('contract', 'live')),
        state TEXT NOT NULL CHECK(state IN ('contract_verified', 'contract_failed',
            'live_verified', 'credentials_missing', 'transport_unavailable',
            'capability_unsupported', 'policy_denied', 'not_configured')),
        fixture_only INTEGER NOT NULL CHECK(fixture_only IN (0, 1)),
        failure_reasons TEXT NOT NULL CHECK(length(failure_reasons) <= 2048),
        cost_known INTEGER NOT NULL CHECK(cost_known IN (0, 1)),
        cost_micro_usd INTEGER CHECK(cost_micro_usd >= 0),
        reservation_id TEXT CHECK(length(reservation_id) <= 36),
        policy_version INTEGER NOT NULL CHECK(policy_version >= 0),
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        CHECK((cost_known = 0 AND cost_micro_usd IS NULL)
           OR (cost_known = 1 AND cost_micro_usd IS NOT NULL)),
        CHECK(NOT (state = 'live_verified' AND fixture_only = 1)),
        CHECK(NOT (state = 'contract_verified' AND track <> 'contract'))
    )""",
    """CREATE INDEX IF NOT EXISTS idx_model_evaluation_org
       ON model_evaluation_records(org_id, connection_id, model, case_id, track, seq)""",
    """CREATE TRIGGER IF NOT EXISTS model_evaluation_records_no_update
       BEFORE UPDATE ON model_evaluation_records
       BEGIN SELECT RAISE(ABORT, 'model evaluation records are immutable'); END""",
    """CREATE TRIGGER IF NOT EXISTS model_evaluation_records_no_delete
       BEFORE DELETE ON model_evaluation_records
       BEGIN SELECT RAISE(ABORT, 'model evaluation records are immutable'); END""",
)
_COLUMNS = (
    "record_id, run_id, org_id, actor_user_id, connection_id, connection_version, "
    "provider, model, case_id, role, track, state, fixture_only, failure_reasons, "
    "cost_known, cost_micro_usd, reservation_id, policy_version, started_at, "
    "finished_at"
)


def clean_reason(text: str) -> str:
    """Bounded, character-restricted reason text that cannot carry secrets."""
    scrubbed = _SECRETISH.sub("[redacted]", str(text))
    return _SAFE_CHARS.sub("?", scrubbed).strip()[:MAX_REASON_LENGTH] or "unspecified"


def _clean_reasons(reasons: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(clean_reason(item) for item in list(reasons)[:MAX_REASONS])


def encode_fixture_body(
    provider: str, model: str, output: dict[str, JsonValue]
) -> dict[str, JsonValue]:
    """Recorded provider-shaped success body carrying ``output`` and no usage."""
    text = json.dumps(output, ensure_ascii=True, allow_nan=False)
    if provider == "anthropic":
        return {
            "model": model,
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": text}],
        }
    if provider == "gemini":
        return {
            "modelVersion": model,
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {"role": "model", "parts": [{"text": text}]},
                }
            ],
        }
    return {
        "model": model,
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": text},
            }
        ],
    }


def _default_cases() -> tuple[EvaluationCaseLike, ...]:
    from terminus.model_gateway.evaluation_cases import all_cases

    return cast("tuple[EvaluationCaseLike, ...]", all_cases())


def valid_live_transport(candidate: object) -> bool:
    """True only for a genuine non-fixture object that declares itself live."""
    return (
        isinstance(candidate, LiveModelTransport)
        and not isinstance(candidate, FixtureModelClient)
        and getattr(candidate, "fixture_only", False) is not True
        and candidate.is_live_transport is True
    )


@dataclass
class _Outcome:
    state: CoverageState
    reasons: tuple[str, ...] = ()
    fixture_only: bool = True
    cost_known: bool = False
    cost_micro_usd: int | None = None
    reservation_id: str | None = None
    policy_version: int | None = None


class ModelEvaluationService:
    """Evaluate configured models; admin-only runs, member-readable coverage."""

    def __init__(
        self,
        routing: ModelRoutingService,
        *,
        cases: Callable[[], tuple[EvaluationCaseLike, ...]] | None = None,
        fixture_output: FixtureOutput | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.routing: ModelRoutingService = routing
        self.db: Database = routing.admission.scheduler.db
        self._cases: Callable[[], tuple[EvaluationCaseLike, ...]] = (
            cases or _default_cases
        )
        self._fixture_output: FixtureOutput = fixture_output or (
            lambda case, connection: case.reference_output()
        )
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        with self.db.transaction() as conn:
            for statement in _SCHEMA:
                _ = conn.execute(statement)

    # -- authorization -----------------------------------------------------

    def _role(self, org_id: str, actor_user_id: str) -> str:
        if not 1 <= len(org_id) <= 200 or not actor_user_id:
            raise EvaluationDeniedError("Model evaluation access denied")
        row = self.db.fetchone(
            "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, actor_user_id),
        )
        if row is None:
            raise EvaluationDeniedError("Model evaluation access denied")
        return str(row["role"])

    def _now(self) -> str:
        return self._clock().astimezone(UTC).isoformat()

    # -- running -----------------------------------------------------------

    async def run(
        self,
        org_id: str,
        actor_user_id: str,
        task_provider: TaskProvider | None = None,
        *,
        live_transports: LiveTransportFactory | None = None,
    ) -> tuple[EvaluationRecord, ...]:
        """Evaluate every configured connection/model on every case (new run id).

        ``task_provider`` maps a case to a scheduler-owned lease and canonical
        evidence ids; without it every pair records ``not_configured``.
        """
        if self._role(org_id, actor_user_id) != "admin":
            raise EvaluationDeniedError("Model evaluation access denied")
        run_id = str(uuid4())
        connections = self.routing.admission.connections.list_for_org(
            org_id, actor_user_id
        )
        cases = self._cases()
        policy_version = self._policy_version(org_id, actor_user_id)
        records: list[EvaluationRecord] = []
        for connection in connections:
            for model in connection.models:
                for case in cases:
                    started = self._now()
                    contract, live = await self._evaluate_pair(
                        org_id,
                        actor_user_id,
                        connection,
                        model,
                        case,
                        task_provider,
                        live_transports,
                    )
                    for track, outcome in (("contract", contract), ("live", live)):
                        records.append(
                            self._append(
                                run_id,
                                org_id,
                                actor_user_id,
                                connection,
                                model,
                                case,
                                cast("Track", track),
                                outcome,
                                policy_version,
                                started,
                            )
                        )
        return tuple(records)

    def _policy_version(self, org_id: str, actor_user_id: str) -> int:
        try:
            return self.routing.admission.policies.get(org_id, actor_user_id).version
        except Exception:
            return 0

    def _append(
        self,
        run_id: str,
        org_id: str,
        actor: str,
        connection: ModelConnectionView,
        model: str,
        case: EvaluationCaseLike,
        track: Track,
        outcome: _Outcome,
        policy_version: int,
        started: str,
    ) -> EvaluationRecord:
        reasons = _clean_reasons(outcome.reasons)
        cost_known = outcome.cost_known and outcome.cost_micro_usd is not None
        record = EvaluationRecord(
            record_id=str(uuid4()),
            run_id=run_id,
            org_id=org_id,
            actor_user_id=actor,
            connection_id=connection.connection_id,
            connection_version=connection.version,
            provider=connection.provider,
            model=model,
            case_id=case.case_id,
            role=case.role,
            track=track,
            state=outcome.state,
            fixture_only=outcome.fixture_only,
            failure_reasons=reasons,
            cost_known=cost_known,
            cost_micro_usd=outcome.cost_micro_usd if cost_known else None,
            reservation_id=outcome.reservation_id,
            policy_version=outcome.policy_version
            if outcome.policy_version is not None
            else policy_version,
            started_at=started,
            finished_at=self._now(),
        )
        _ = self.db.execute(
            f"""INSERT INTO model_evaluation_records ({_COLUMNS})
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",  # noqa: S608
            (
                record.record_id,
                record.run_id,
                record.org_id,
                record.actor_user_id,
                record.connection_id,
                record.connection_version,
                record.provider,
                record.model,
                record.case_id,
                record.role,
                record.track,
                record.state,
                int(record.fixture_only),
                json.dumps(list(record.failure_reasons)),
                int(record.cost_known),
                record.cost_micro_usd,
                record.reservation_id,
                record.policy_version,
                record.started_at,
                record.finished_at,
            ),
        )
        return record

    async def _evaluate_pair(
        self,
        org_id: str,
        actor: str,
        connection: ModelConnectionView,
        model: str,
        case: EvaluationCaseLike,
        task_provider: TaskProvider | None,
        live_transports: LiveTransportFactory | None,
    ) -> tuple[_Outcome, _Outcome]:
        if not connection.enabled:
            both = _Outcome("not_configured", ("connection_disabled",))
            return both, both
        required = cast("frozenset[Capability]", case.required_capabilities) or (
            DEFAULT_CAPABILITIES
        )
        unsupported = sorted(
            set(required)
            - (PROVIDER_CAPABILITIES[connection.provider] & ADMITTED_CAPABILITIES)
        )
        if unsupported:
            both = _Outcome(
                "capability_unsupported",
                tuple(f"unsupported:{name}" for name in unsupported),
            )
            return both, both
        task = None if task_provider is None else task_provider(case)
        if task is None:
            both = _Outcome("not_configured", ("no_evaluation_task",))
            return both, both
        if task.lease.task.role != case.role:
            both = _Outcome("not_configured", ("task_role_mismatch",))
            return both, both
        contract = await self._run_contract(
            org_id, actor, connection, model, case, task, required
        )
        live = await self._run_live(
            org_id, actor, connection, model, case, task, live_transports
        )
        return contract, live

    # -- contract track ----------------------------------------------------

    def _route_reasons(
        self, org_id: str, since_rowid: int, connection_id: str
    ) -> list[str]:
        rows = self.db.fetchall(
            """SELECT kind, outcome, connection_id FROM model_routing_audit
               WHERE rowid > ? AND org_id = ? ORDER BY rowid""",
            (since_rowid, org_id),
        )
        found = [
            str(row["outcome"])
            for row in rows
            if row["kind"] in {"excluded", "denied"}
            and row["connection_id"] in {None, connection_id}
        ]
        return list(dict.fromkeys(found)) or ["route_denied"]

    async def _run_contract(  # noqa: PLR0911
        self,
        org_id: str,
        actor: str,
        connection: ModelConnectionView,
        model: str,
        case: EvaluationCaseLike,
        task: EvaluationTask,
        required: frozenset[Capability],
    ) -> _Outcome:
        try:
            output = self._fixture_output(case, connection)
            body = encode_fixture_body(connection.provider, model, output)
        except Exception as exc:
            return _Outcome(
                "contract_failed", (f"fixture_output:{type(exc).__name__}",)
            )

        def make_client(candidate: ModelConnectionView) -> FixtureModelClient | None:
            if candidate.connection_id != connection.connection_id:
                return None
            return FixtureModelClient(
                candidate.provider,
                httpx2.MockTransport(lambda request: httpx2.Response(200, json=body)),
                base_url=candidate.base_url,
            )

        marker = self.db.fetchone(
            "SELECT COALESCE(MAX(rowid), 0) AS m FROM model_routing_audit"
        )
        since = int(marker["m"]) if marker else 0
        try:
            result = await self.routing.route_fixture(
                task.lease,
                actor,
                task.evidence_ids,
                make_client,
                capabilities=required,
                preferred=RouteRef(connection_id=connection.connection_id, model=model),
                max_attempts=1,
                output_schema=case.output_schema,
            )
        except ModelRoutingDeniedError:
            return _Outcome(
                "policy_denied",
                tuple(self._route_reasons(org_id, since, connection.connection_id)),
            )
        except Exception as exc:
            return _Outcome("contract_failed", (f"harness_error:{type(exc).__name__}",))
        attempt = result.selected

        def finish(state: CoverageState, reasons: tuple[str, ...]) -> _Outcome:
            return _Outcome(
                state,
                reasons,
                cost_known=attempt.cost_known,
                cost_micro_usd=attempt.cost_micro_usd,
                reservation_id=attempt.reservation_id,
                policy_version=attempt.policy_version,
            )

        response = result.response
        if response.status != "ok" or response.output is None:
            code = response.error_code or response.status
            return finish("contract_failed", (f"response:{code}",))
        try:
            problems = case.validate_output(response.output)
        except Exception as exc:
            return finish("contract_failed", (f"validator:{type(exc).__name__}",))
        if problems:
            return finish("contract_failed", tuple(problems))
        return finish("contract_verified", ())

    # -- live track --------------------------------------------------------

    async def _run_live(
        self,
        org_id: str,
        actor: str,
        connection: ModelConnectionView,
        model: str,
        case: EvaluationCaseLike,
        task: EvaluationTask,
        live_transports: LiveTransportFactory | None,
    ) -> _Outcome:
        if connection.provider != "local" and not connection.credential_configured:
            return _Outcome("credentials_missing", ("no_credential_configured",))
        transport = None if live_transports is None else live_transports(connection)
        if transport is None:
            return _Outcome("transport_unavailable", ("no_live_transport",))
        if not valid_live_transport(transport):
            return _Outcome("transport_unavailable", ("live_transport_rejected",))
        return await self._call_live(
            org_id, actor, connection, model, case, task, transport
        )

    async def _call_live(
        self,
        org_id: str,
        actor: str,
        connection: ModelConnectionView,
        model: str,
        case: EvaluationCaseLike,
        task: EvaluationTask,
        transport: LiveModelTransport,
    ) -> _Outcome:
        admission = self.routing.admission
        budgets = self.routing.budgets
        try:
            call = await admission.prepare(
                task.lease,
                actor,
                connection.connection_id,
                model,
                task.evidence_ids,
                output_schema=case.output_schema,
            )
            reservation = budgets.reserve(
                org_id,
                actor,
                ReservationRequest(
                    idempotency_key=f"eval-live:{uuid4()}",
                    incident_id=call.incident_id,
                    task_id=call.task_id,
                    run_id=call.run_id,
                    connection_id=connection.connection_id,
                    connection_version=connection.version,
                    model=model,
                    request_bytes=len(call.request.model_dump_json().encode()),
                    max_output_tokens=call.request.max_output_tokens,
                ),
            )
        except (ValueError, LookupError):
            return _Outcome(
                "policy_denied", ("live_admission_denied",), fixture_only=False
            )
        rid = reservation.reservation_id
        try:
            await admission.authorize(call)
            response = await transport.respond(call.request)
        except asyncio.CancelledError:
            _ = budgets.mark_ambiguous(org_id, rid)
            raise
        except Exception as exc:
            _ = budgets.mark_ambiguous(org_id, rid)
            return _Outcome(
                "transport_unavailable",
                (f"live_call_failed:{type(exc).__name__}",),
                fixture_only=False,
                reservation_id=rid,
            )
        usage = response.usage
        try:
            settled = budgets.settle(
                org_id,
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
            settled = budgets.mark_ambiguous(org_id, rid, reason_code="settle_failed")
        cost = (
            settled.actual_cost_micro_usd
            if settled.state in ("settled", "reconciled")
            else None
        )

        def finish(state: CoverageState, reasons: tuple[str, ...]) -> _Outcome:
            return _Outcome(
                state,
                reasons,
                fixture_only=False,
                cost_known=cost is not None,
                cost_micro_usd=cost,
                reservation_id=rid,
                policy_version=call.policy_version,
            )

        if response.status != "ok" or response.output is None:
            return finish(
                "contract_failed",
                (f"response:{response.error_code or response.status}",),
            )
        problems = case.validate_output(response.output)
        if problems:
            return finish("contract_failed", tuple(problems))
        return finish("live_verified", ())

    # -- reads ---------------------------------------------------------------

    @staticmethod
    def _record(row: dict[str, object]) -> EvaluationRecord:
        values = dict(row)
        values["failure_reasons"] = tuple(json.loads(str(values["failure_reasons"])))
        values["fixture_only"] = bool(values["fixture_only"])
        values["cost_known"] = bool(values["cost_known"])
        return EvaluationRecord.model_validate(values)

    def list_records(
        self,
        org_id: str,
        actor_user_id: str,
        run_id: str | None = None,
        limit: int = 500,
    ) -> tuple[EvaluationRecord, ...]:
        """Records (oldest first) for the organization only."""
        _ = self._role(org_id, actor_user_id)
        if type(limit) is not int or not 1 <= limit <= 5000:
            raise EvaluationValidationError("Invalid limit")
        sql = f"SELECT {_COLUMNS} FROM model_evaluation_records WHERE org_id = ?"  # noqa: S608
        params: tuple[object, ...] = (org_id,)
        if run_id is not None:
            sql += " AND run_id = ?"
            params = (org_id, run_id)
        rows = self.db.fetchall(sql + " ORDER BY seq LIMIT ?", (*params, limit))
        return tuple(self._record(row) for row in rows)

    def _latest(self, org_id: str) -> list[EvaluationRecord]:
        rows = self.db.fetchall(
            f"""SELECT {_COLUMNS} FROM model_evaluation_records
               WHERE seq IN (SELECT MAX(seq) FROM model_evaluation_records
               WHERE org_id = ? GROUP BY connection_id, connection_version, model,
               case_id, track) ORDER BY seq""",  # noqa: S608
            (org_id,),
        )
        return [self._record(row) for row in rows]

    def coverage_summary(
        self,
        org_id: str,
        actor_user_id: str,
        *,
        demo_model: RouteRef | None = None,
        demo_case_ids: frozenset[str] | None = None,
    ) -> CoverageSummary:
        """Latest-record coverage per connection/model; live is never inferred.

        ``demo_ready`` is True only when the demo model's latest record on the
        connection's current version is ``live_verified`` for every required case.
        """
        _ = self._role(org_id, actor_user_id)
        latest = self._latest(org_id)
        groups: dict[tuple[str, int, str, str], list[EvaluationRecord]] = {}
        for record in latest:
            key = (
                record.connection_id,
                record.connection_version,
                record.provider,
                record.model,
            )
            groups.setdefault(key, []).append(record)
        pairs: list[PairCoverage] = []
        for (cid, version, provider, model), items in groups.items():
            counts = Counter(item.state for item in items)
            contract = Counter(i.state for i in items if i.track == "contract")
            live = Counter(i.state for i in items if i.track == "live")
            pairs.append(
                PairCoverage(
                    connection_id=cid,
                    connection_version=version,
                    provider=provider,
                    model=model,
                    counts=dict(counts),
                    contract_counts=dict(contract),
                    live_counts=dict(live),
                    contract_verified_count=counts["contract_verified"],
                    live_verified_count=live["live_verified"],
                    unknown_cost_count=sum(
                        1 for i in items if not i.cost_known and i.reservation_id
                    ),
                    last_run_id=items[-1].run_id,
                )
            )
        live_total = sum(p.live_verified_count for p in pairs)
        contract_total = sum(p.contract_verified_count for p in pairs)
        required, missing, ready = self._demo(
            org_id, actor_user_id, latest, demo_model, demo_case_ids
        )
        return CoverageSummary(
            org_id=org_id,
            pairs=tuple(pairs),
            live_verified_count=live_total,
            contract_verified_count=contract_total,
            demo_model=demo_model,
            demo_required_case_ids=required,
            demo_missing_live_case_ids=missing,
            demo_ready=ready,
            note=(
                "contract_verified is fixture-only evidence and is not live coverage; "
                "only live_verified counts as live"
            ),
        )

    def _demo(
        self,
        org_id: str,
        actor_user_id: str,
        latest: list[EvaluationRecord],
        demo_model: RouteRef | None,
        demo_case_ids: frozenset[str] | None,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool]:
        if demo_model is None:
            return (), (), False
        required = (
            tuple(sorted(demo_case_ids))
            if demo_case_ids is not None
            else tuple(sorted(case.case_id for case in self._cases()))
        )
        try:
            current = self.routing.admission.connections.get(
                org_id, actor_user_id, demo_model.connection_id
            ).version
        except Exception:
            return required, required, False
        verified = {
            r.case_id
            for r in latest
            if r.track == "live"
            and r.state == "live_verified"
            and not r.fixture_only
            and r.connection_id == demo_model.connection_id
            and r.connection_version == current
            and r.model == demo_model.model
        }
        missing = tuple(case_id for case_id in required if case_id not in verified)
        return required, missing, bool(required) and not missing


__all__ = [
    "COVERAGE_STATES",
    "CoverageState",
    "CoverageSummary",
    "EvaluationDeniedError",
    "EvaluationRecord",
    "EvaluationTask",
    "EvaluationValidationError",
    "LiveModelTransport",
    "ModelEvaluationService",
    "PairCoverage",
    "clean_reason",
    "encode_fixture_body",
    "valid_live_transport",
]
