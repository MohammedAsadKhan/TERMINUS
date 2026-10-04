"""Atomic organization-level financial reservations and a durable usage ledger.

Money is stored as integer micro-USD and tokens as integers. Limits apply per
organization and budget window, never per connection, key, retry or fallback.
Unknown usage or cost is never treated as zero: it is stored as NULL, the
reservation stays ``ambiguous`` and its full conservative bound remains counted
as exposure until an administrator reconciles it.
"""

# pyright: reportAny=false

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Annotated, ClassVar, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from terminus.storage.db import Database

ReservationState = Literal["reserved", "settled", "released", "ambiguous", "reconciled"]
LedgerAction = Literal[
    "reserve", "settle", "release", "mark_ambiguous", "reconcile", "recover_stale"
]

_IDENTIFIER = r"\S"
_REASON_PATTERN = r"^[a-z0-9_]{1,64}$"
_REASON = re.compile(_REASON_PATTERN)
_MODEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$"
_WINDOW = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_MILLION = 1_000_000
_MAX_TOKENS = 10_000_000_000
_MAX_PRICE = 1_000_000_000_000
_MAX_LIMIT = 1_000_000_000_000_000

_Id = Annotated[str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER)]
_Tokens = Annotated[int, Field(ge=0, le=_MAX_TOKENS)]
_Price = Annotated[int, Field(ge=0, le=_MAX_PRICE)]
_Reason = Annotated[str, Field(pattern=_REASON_PATTERN)]


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )


class UsageReport(_Contract):
    """Provider-reported usage. ``None`` means the provider did not report it."""

    input_tokens: _Tokens | None = None
    output_tokens: _Tokens | None = None
    cached_input_tokens: _Tokens | None = None
    reasoning_tokens: _Tokens | None = None


class ModelPrice(_Contract):
    """Per-million-token micro-USD rates for one connection and model."""

    org_id: _Id
    connection_id: _Id
    model: Annotated[str, Field(pattern=_MODEL_PATTERN)]
    input_per_mtok_micro_usd: _Price
    output_per_mtok_micro_usd: _Price
    cached_input_per_mtok_micro_usd: _Price | None = None
    reasoning_per_mtok_micro_usd: _Price | None = None
    version: Annotated[int, Field(ge=1)]


class ModelBudget(_Contract):
    """Organization spend limit for one UTC-day window."""

    org_id: _Id
    window_key: Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]
    limit_micro_usd: Annotated[int, Field(ge=0, le=_MAX_LIMIT)]
    limit_tokens: Annotated[int, Field(ge=0, le=_MAX_LIMIT)] | None = None
    version: Annotated[int, Field(ge=1)]


class ReservationRequest(_Contract):
    """Intent to make one provider attempt; persisted before any external I/O."""

    idempotency_key: _Id
    incident_id: _Id
    task_id: _Id
    run_id: _Id | None = None
    connection_id: _Id
    connection_version: Annotated[int, Field(ge=1)]
    model: Annotated[str, Field(pattern=_MODEL_PATTERN)]
    request_bytes: Annotated[int, Field(ge=0, le=_MAX_TOKENS)]
    max_output_tokens: Annotated[int, Field(ge=1, le=_MAX_TOKENS)]
    max_input_tokens: Annotated[int, Field(ge=0, le=_MAX_TOKENS)] | None = None


class ModelReservation(_Contract):
    """Current state of one financial reservation."""

    reservation_id: _Id
    org_id: _Id
    window_key: str
    incident_id: _Id
    task_id: _Id
    run_id: _Id | None
    idempotency_key: _Id
    connection_id: _Id
    connection_version: int
    model: str
    reserved_micro_usd: int
    reserved_tokens: int
    state: ReservationState
    actual_cost_micro_usd: int | None
    actual_tokens: int | None
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    reasoning_tokens: int | None
    created_at: str
    updated_at: str


class LedgerEntry(_Contract):
    """One immutable state transition."""

    seq: int
    org_id: str
    reservation_id: str
    action: LedgerAction
    from_state: str | None
    to_state: str
    window_key: str
    connection_id: str
    model: str
    reserved_micro_usd: int
    input_tokens: int | None
    output_tokens: int | None
    cached_input_tokens: int | None
    reasoning_tokens: int | None
    cost_known: bool
    cost_micro_usd: int | None
    reason_code: str
    actor_user_id: str | None
    created_at: str


class UsageSummary(_Contract):
    """Window totals; unknown cost is reported separately, never as zero."""

    org_id: str
    window_key: str
    limit_micro_usd: int | None
    limit_tokens: int | None
    known_cost_micro_usd: int
    unknown_cost_count: int
    ambiguous_exposure_micro_usd: int
    reserved_exposure_micro_usd: int
    exposure_micro_usd: int
    remaining_micro_usd: int | None
    over_limit: bool


class BudgetDeniedError(ValueError):
    """The live tenant membership does not authorize the operation."""


class BudgetExceededError(ValueError):
    """The reservation would exceed the organization limit or cannot be bounded."""


class BudgetConflictError(ValueError):
    """The request conflicts with current durable state."""


class BudgetNotFoundError(LookupError):
    """A tenant-scoped ledger resource does not exist."""


class BudgetValidationError(ValueError):
    """A request or stored record is invalid."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS model_prices (
    org_id TEXT NOT NULL,
    connection_id TEXT NOT NULL CHECK(length(connection_id) BETWEEN 1 AND 200),
    model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
    input_per_mtok INTEGER NOT NULL CHECK(input_per_mtok >= 0),
    output_per_mtok INTEGER NOT NULL CHECK(output_per_mtok >= 0),
    cached_input_per_mtok INTEGER CHECK(cached_input_per_mtok >= 0),
    reasoning_per_mtok INTEGER CHECK(reasoning_per_mtok >= 0),
    version INTEGER NOT NULL CHECK(version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(org_id, connection_id, model),
    FOREIGN KEY(org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS model_budgets (
    org_id TEXT NOT NULL,
    window_key TEXT NOT NULL CHECK(length(window_key) = 10),
    limit_micro_usd INTEGER NOT NULL CHECK(limit_micro_usd >= 0),
    limit_tokens INTEGER CHECK(limit_tokens >= 0),
    version INTEGER NOT NULL CHECK(version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(org_id, window_key),
    FOREIGN KEY(org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS model_budget_audit (
    audit_id TEXT PRIMARY KEY CHECK(length(audit_id) <= 36),
    org_id TEXT NOT NULL CHECK(length(org_id) <= 200),
    actor_user_id TEXT NOT NULL CHECK(length(actor_user_id) <= 200),
    action TEXT NOT NULL CHECK(action IN ('put_price', 'put_budget')),
    subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 450),
    subject_version INTEGER NOT NULL CHECK(subject_version >= 1),
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS model_budget_audit_no_update
BEFORE UPDATE ON model_budget_audit
BEGIN SELECT RAISE(ABORT, 'model budget audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS model_budget_audit_no_delete
BEFORE DELETE ON model_budget_audit
BEGIN SELECT RAISE(ABORT, 'model budget audit is immutable'); END;
CREATE TABLE IF NOT EXISTS model_reservations (
    reservation_id TEXT PRIMARY KEY CHECK(length(reservation_id) <= 36),
    org_id TEXT NOT NULL,
    window_key TEXT NOT NULL,
    incident_id TEXT NOT NULL CHECK(length(incident_id) BETWEEN 1 AND 200),
    task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 200),
    run_id TEXT CHECK(length(run_id) BETWEEN 1 AND 200),
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
    connection_id TEXT NOT NULL CHECK(length(connection_id) BETWEEN 1 AND 200),
    connection_version INTEGER NOT NULL CHECK(connection_version >= 1),
    model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
    price_input INTEGER NOT NULL,
    price_output INTEGER NOT NULL,
    price_cached_input INTEGER,
    price_reasoning INTEGER,
    reserved_micro_usd INTEGER NOT NULL CHECK(reserved_micro_usd >= 0),
    reserved_tokens INTEGER NOT NULL CHECK(reserved_tokens >= 0),
    state TEXT NOT NULL CHECK(state IN
        ('reserved', 'settled', 'released', 'ambiguous', 'reconciled')),
    actual_cost_micro_usd INTEGER CHECK(actual_cost_micro_usd >= 0),
    actual_tokens INTEGER CHECK(actual_tokens >= 0),
    input_tokens INTEGER CHECK(input_tokens >= 0),
    output_tokens INTEGER CHECK(output_tokens >= 0),
    cached_input_tokens INTEGER CHECK(cached_input_tokens >= 0),
    reasoning_tokens INTEGER CHECK(reasoning_tokens >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(org_id, idempotency_key),
    FOREIGN KEY(org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_model_reservations_window
ON model_reservations(org_id, window_key, state);
CREATE TABLE IF NOT EXISTS model_usage_ledger (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL CHECK(length(org_id) <= 200),
    reservation_id TEXT NOT NULL CHECK(length(reservation_id) <= 36),
    action TEXT NOT NULL CHECK(action IN
        ('reserve', 'settle', 'release', 'mark_ambiguous', 'reconcile',
         'recover_stale')),
    from_state TEXT,
    to_state TEXT NOT NULL,
    window_key TEXT NOT NULL,
    connection_id TEXT NOT NULL CHECK(length(connection_id) <= 200),
    model TEXT NOT NULL CHECK(length(model) <= 128),
    reserved_micro_usd INTEGER NOT NULL,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cached_input_tokens INTEGER,
    reasoning_tokens INTEGER,
    cost_known INTEGER NOT NULL CHECK(cost_known IN (0, 1)),
    cost_micro_usd INTEGER,
    reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 64),
    actor_user_id TEXT CHECK(length(actor_user_id) <= 200),
    created_at TEXT NOT NULL,
    CHECK((cost_known = 0 AND cost_micro_usd IS NULL)
       OR (cost_known = 1 AND cost_micro_usd IS NOT NULL AND cost_micro_usd >= 0))
);
CREATE INDEX IF NOT EXISTS idx_model_usage_ledger_org
ON model_usage_ledger(org_id, reservation_id, seq);
CREATE TRIGGER IF NOT EXISTS model_usage_ledger_no_update
BEFORE UPDATE ON model_usage_ledger
BEGIN SELECT RAISE(ABORT, 'model usage ledger is immutable'); END;
CREATE TRIGGER IF NOT EXISTS model_usage_ledger_no_delete
BEFORE DELETE ON model_usage_ledger
BEGIN SELECT RAISE(ABORT, 'model usage ledger is immutable'); END;
"""

_RESERVATION_COLUMNS = "reservation_id, org_id, window_key, incident_id, task_id, run_id, idempotency_key, connection_id, connection_version, model, reserved_micro_usd, reserved_tokens, state, actual_cost_micro_usd, actual_tokens, input_tokens, output_tokens, cached_input_tokens, reasoning_tokens, created_at, updated_at"
_LEDGER_COLUMNS = "seq, org_id, reservation_id, action, from_state, to_state, window_key, connection_id, model, reserved_micro_usd, input_tokens, output_tokens, cached_input_tokens, reasoning_tokens, cost_known, cost_micro_usd, reason_code, actor_user_id, created_at"


def window_key_for(moment: datetime) -> str:
    """Return the UTC-day budget window key for a moment."""
    return moment.astimezone(UTC).strftime("%Y-%m-%d")


def _ceil_div(numerator: int, denominator: int) -> int:
    return -(-numerator // denominator)


def _price_cost(
    input_rate: int,
    output_rate: int,
    cached_rate: int | None,
    reasoning_rate: int | None,
    usage: UsageReport,
) -> int | None:
    """Cost in micro-USD, or None when any billable component is unknown."""
    if usage.input_tokens is None or usage.output_tokens is None:
        return None
    effective_cached = input_rate if cached_rate is None else cached_rate
    effective_reasoning = output_rate if reasoning_rate is None else reasoning_rate
    cached = usage.cached_input_tokens
    if cached is None:
        if effective_cached != input_rate:
            return None
        cached = 0
    reasoning = usage.reasoning_tokens
    if reasoning is None:
        if effective_reasoning != output_rate:
            return None
        reasoning = 0
    if cached > usage.input_tokens or reasoning > usage.output_tokens:
        return None
    total = (
        (usage.input_tokens - cached) * input_rate
        + cached * effective_cached
        + (usage.output_tokens - reasoning) * output_rate
        + reasoning * effective_reasoning
    )
    return _ceil_div(total, _MILLION)


class ModelBudgetStore:
    """Prices, budgets, atomic reservations and the immutable usage ledger."""

    def __init__(
        self, db: Database, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.db: Database = db
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(UTC))
        with self.db.transaction() as conn:
            statement = ""
            for line in _SCHEMA.splitlines():
                statement += f"{line}\n"
                if sqlite3.complete_statement(statement):
                    _ = conn.execute(statement)
                    statement = ""

    # -- helpers -----------------------------------------------------------

    def _now(self) -> datetime:
        return self._clock().astimezone(UTC)

    @staticmethod
    def _authorize(
        conn: sqlite3.Connection,
        org_id: str,
        actor_user_id: str,
        level: Literal["read", "use", "admin"] = "use",
    ) -> None:
        row = conn.execute(
            "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, actor_user_id),
        ).fetchone()
        allowed = {
            "read": ("admin", "member", "viewer"),
            "use": ("admin", "member"),
            "admin": ("admin",),
        }[level]
        if row is None or str(row["role"]) not in allowed:
            raise BudgetDeniedError("Model budget access denied")

    @staticmethod
    def _check_org(org_id: str) -> None:
        if not 1 <= len(org_id) <= 200 or " " in org_id:
            raise BudgetValidationError("Invalid organization")

    @staticmethod
    def _validate[T: BaseModel](kind: type[T], /, **values: object) -> T:
        try:
            return kind.model_validate(values)
        except (TypeError, ValueError, ValidationError) as exc:
            raise BudgetValidationError("Invalid model budget request") from exc

    @staticmethod
    def _reason(reason_code: str) -> str:
        if not _REASON.fullmatch(reason_code):
            raise BudgetValidationError("Invalid reason code")
        return reason_code

    @staticmethod
    def _reservation(row: sqlite3.Row) -> ModelReservation:
        try:
            return ModelReservation.model_validate(
                {key: row[key] for key in row.keys()}  # noqa: SIM118
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise BudgetValidationError("Stored reservation is invalid") from exc

    @staticmethod
    def _entry(row: sqlite3.Row) -> LedgerEntry:
        values = {key: row[key] for key in row.keys()}  # noqa: SIM118
        values["cost_known"] = bool(values["cost_known"])
        try:
            return LedgerEntry.model_validate(values)
        except (TypeError, ValueError, ValidationError) as exc:
            raise BudgetValidationError("Stored ledger entry is invalid") from exc

    @staticmethod
    def _load(
        conn: sqlite3.Connection, org_id: str, reservation_id: str
    ) -> sqlite3.Row:
        row = conn.execute(
            "SELECT * FROM model_reservations WHERE org_id = ? AND reservation_id = ?",
            (org_id, reservation_id),
        ).fetchone()
        if row is None:
            raise BudgetNotFoundError("Model reservation not found")
        return row

    @staticmethod
    def _public(
        conn: sqlite3.Connection, org_id: str, reservation_id: str
    ) -> ModelReservation:
        row = conn.execute(
            f"SELECT {_RESERVATION_COLUMNS} FROM model_reservations WHERE org_id = ? AND reservation_id = ?",  # noqa: S608
            (org_id, reservation_id),
        ).fetchone()
        if row is None:
            raise BudgetNotFoundError("Model reservation not found")
        return ModelBudgetStore._reservation(row)

    @staticmethod
    def _append(
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        action: LedgerAction,
        to_state: str,
        usage: UsageReport | None,
        cost: int | None,
        reason_code: str,
        actor_user_id: str | None,
        timestamp: str,
    ) -> None:
        usage = usage or UsageReport()
        _ = conn.execute(
            """INSERT INTO model_usage_ledger
               (org_id, reservation_id, action, from_state, to_state, window_key,
                connection_id, model, reserved_micro_usd, input_tokens,
                output_tokens, cached_input_tokens, reasoning_tokens, cost_known,
                cost_micro_usd, reason_code, actor_user_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["org_id"],
                row["reservation_id"],
                action,
                None if action == "reserve" else row["state"],
                to_state,
                row["window_key"],
                row["connection_id"],
                row["model"],
                row["reserved_micro_usd"],
                usage.input_tokens,
                usage.output_tokens,
                usage.cached_input_tokens,
                usage.reasoning_tokens,
                int(cost is not None),
                cost,
                reason_code,
                actor_user_id,
                timestamp,
            ),
        )

    @staticmethod
    def _exposure(
        conn: sqlite3.Connection, org_id: str, window_key: str
    ) -> tuple[int, int]:
        """Organization exposure (micro-USD, tokens) across every connection."""
        row = conn.execute(
            """SELECT
                 COALESCE(SUM(CASE WHEN state IN ('reserved', 'ambiguous')
                     THEN reserved_micro_usd
                     WHEN state IN ('settled', 'reconciled')
                     THEN COALESCE(actual_cost_micro_usd, reserved_micro_usd)
                     ELSE 0 END), 0) AS usd,
                 COALESCE(SUM(CASE WHEN state IN ('reserved', 'ambiguous')
                     THEN reserved_tokens
                     WHEN state IN ('settled', 'reconciled')
                     THEN COALESCE(actual_tokens, reserved_tokens)
                     ELSE 0 END), 0) AS tokens
               FROM model_reservations WHERE org_id = ? AND window_key = ?""",
            (org_id, window_key),
        ).fetchone()
        return int(row["usd"]), int(row["tokens"])

    # -- prices and budgets --------------------------------------------------

    def put_price(
        self,
        org_id: str,
        actor_user_id: str,
        connection_id: str,
        model: str,
        *,
        input_per_mtok_micro_usd: int,
        output_per_mtok_micro_usd: int,
        cached_input_per_mtok_micro_usd: int | None = None,
        reasoning_per_mtok_micro_usd: int | None = None,
        expected_version: int = 0,
    ) -> ModelPrice:
        """Create or replace a price (admin only, compare-and-swap)."""
        self._check_org(org_id)
        if type(expected_version) is not int or expected_version < 0:
            raise BudgetValidationError("Invalid expected version")
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "admin")
            current = conn.execute(
                "SELECT version FROM model_prices WHERE org_id = ? AND connection_id = ? AND model = ?",
                (org_id, connection_id, model),
            ).fetchone()
            current_version = 0 if current is None else int(current["version"])
            if current_version != expected_version:
                raise BudgetConflictError("Model price version conflict")
            price = self._validate(
                ModelPrice,
                org_id=org_id,
                connection_id=connection_id,
                model=model,
                input_per_mtok_micro_usd=input_per_mtok_micro_usd,
                output_per_mtok_micro_usd=output_per_mtok_micro_usd,
                cached_input_per_mtok_micro_usd=cached_input_per_mtok_micro_usd,
                reasoning_per_mtok_micro_usd=reasoning_per_mtok_micro_usd,
                version=current_version + 1,
            )
            now = self._now().isoformat()
            values = (
                price.input_per_mtok_micro_usd,
                price.output_per_mtok_micro_usd,
                price.cached_input_per_mtok_micro_usd,
                price.reasoning_per_mtok_micro_usd,
                price.version,
                now,
                org_id,
                connection_id,
                model,
            )
            if current is None:
                _ = conn.execute(
                    """INSERT INTO model_prices
                       (input_per_mtok, output_per_mtok, cached_input_per_mtok,
                        reasoning_per_mtok, version, updated_at, org_id,
                        connection_id, model)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    values,
                )
            else:
                cursor = conn.execute(
                    """UPDATE model_prices SET input_per_mtok = ?,
                       output_per_mtok = ?, cached_input_per_mtok = ?,
                       reasoning_per_mtok = ?, version = ?, updated_at = ?
                       WHERE org_id = ? AND connection_id = ? AND model = ?
                         AND version = ?""",
                    (*values, expected_version),
                )
                if cursor.rowcount != 1:
                    raise BudgetConflictError("Model price version conflict")
            self._audit(
                conn,
                org_id,
                actor_user_id,
                "put_price",
                f"{connection_id}/{model}",
                price.version,
                now,
            )
            return price

    @staticmethod
    def _audit(
        conn: sqlite3.Connection,
        org_id: str,
        actor_user_id: str,
        action: Literal["put_price", "put_budget"],
        subject: str,
        version: int,
        timestamp: str,
    ) -> None:
        _ = conn.execute(
            """INSERT INTO model_budget_audit
               (audit_id, org_id, actor_user_id, action, subject,
                subject_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid4()),
                org_id,
                actor_user_id,
                action,
                subject[:450],
                version,
                timestamp,
            ),
        )

    def get_price(
        self, org_id: str, actor_user_id: str, connection_id: str, model: str
    ) -> ModelPrice:
        """Read a price using live membership."""
        self._check_org(org_id)
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "read")
            row = conn.execute(
                "SELECT * FROM model_prices WHERE org_id = ? AND connection_id = ? AND model = ?",
                (org_id, connection_id, model),
            ).fetchone()
            if row is None:
                raise BudgetNotFoundError("Model price not found")
            return self._validate(
                ModelPrice,
                org_id=org_id,
                connection_id=connection_id,
                model=model,
                input_per_mtok_micro_usd=row["input_per_mtok"],
                output_per_mtok_micro_usd=row["output_per_mtok"],
                cached_input_per_mtok_micro_usd=row["cached_input_per_mtok"],
                reasoning_per_mtok_micro_usd=row["reasoning_per_mtok"],
                version=row["version"],
            )

    def put_budget(
        self,
        org_id: str,
        actor_user_id: str,
        window_key: str,
        *,
        limit_micro_usd: int,
        limit_tokens: int | None = None,
        expected_version: int = 0,
    ) -> ModelBudget:
        """Create or replace an organization window limit (admin, CAS)."""
        self._check_org(org_id)
        if type(expected_version) is not int or expected_version < 0:
            raise BudgetValidationError("Invalid expected version")
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "admin")
            self._check_window(window_key)
            current = conn.execute(
                "SELECT version FROM model_budgets WHERE org_id = ? AND window_key = ?",
                (org_id, window_key),
            ).fetchone()
            current_version = 0 if current is None else int(current["version"])
            if current_version != expected_version:
                raise BudgetConflictError("Model budget version conflict")
            budget = self._validate(
                ModelBudget,
                org_id=org_id,
                window_key=window_key,
                limit_micro_usd=limit_micro_usd,
                limit_tokens=limit_tokens,
                version=current_version + 1,
            )
            now = self._now().isoformat()
            if current is None:
                _ = conn.execute(
                    """INSERT INTO model_budgets
                       (org_id, window_key, limit_micro_usd, limit_tokens, version,
                        updated_at) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        org_id,
                        window_key,
                        limit_micro_usd,
                        limit_tokens,
                        budget.version,
                        now,
                    ),
                )
            else:
                cursor = conn.execute(
                    """UPDATE model_budgets SET limit_micro_usd = ?, limit_tokens = ?,
                       version = ?, updated_at = ?
                       WHERE org_id = ? AND window_key = ? AND version = ?""",
                    (
                        limit_micro_usd,
                        limit_tokens,
                        budget.version,
                        now,
                        org_id,
                        window_key,
                        expected_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BudgetConflictError("Model budget version conflict")
            self._audit(
                conn,
                org_id,
                actor_user_id,
                "put_budget",
                window_key,
                budget.version,
                now,
            )
            return budget

    @staticmethod
    def _check_window(window_key: str) -> None:
        if not _WINDOW.fullmatch(window_key):
            raise BudgetValidationError("Invalid budget window")
        try:
            _ = date.fromisoformat(window_key)
        except ValueError as exc:
            raise BudgetValidationError("Invalid budget window") from exc

    # -- reservations --------------------------------------------------------

    @staticmethod
    def _fingerprint(request: ReservationRequest) -> str:
        payload = json.dumps(
            request.model_dump(mode="json", exclude={"idempotency_key"}),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def reserve(
        self, org_id: str, actor_user_id: str, request: ReservationRequest
    ) -> ModelReservation:
        """Atomically reserve a conservative cost bound under the org limit.

        Must be called (and committed) before any provider I/O. Replaying the
        same idempotency key with identical parameters returns the original
        reservation; different parameters raise ``BudgetConflictError``.
        """
        self._check_org(org_id)
        request = self._validate(ReservationRequest, **dict(request))
        fingerprint = self._fingerprint(request)
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id)
            existing = conn.execute(
                "SELECT reservation_id, request_fingerprint FROM model_reservations WHERE org_id = ? AND idempotency_key = ?",
                (org_id, request.idempotency_key),
            ).fetchone()
            if existing is not None:
                if str(existing["request_fingerprint"]) != fingerprint:
                    raise BudgetConflictError(
                        "Idempotency key reused with different request"
                    )
                return self._public(conn, org_id, str(existing["reservation_id"]))
            price = conn.execute(
                "SELECT input_per_mtok, output_per_mtok, cached_input_per_mtok, reasoning_per_mtok FROM model_prices WHERE org_id = ? AND connection_id = ? AND model = ?",
                (org_id, request.connection_id, request.model),
            ).fetchone()
            if price is None:
                raise BudgetExceededError(
                    "Model cost cannot be bounded: no price configured"
                )
            now = self._now()
            window = window_key_for(now)
            budget = conn.execute(
                "SELECT limit_micro_usd, limit_tokens FROM model_budgets WHERE org_id = ? AND window_key = ?",
                (org_id, window),
            ).fetchone()
            if budget is None:
                raise BudgetExceededError("No organization budget is configured")
            input_bound = (
                request.request_bytes
                if request.max_input_tokens is None
                else request.max_input_tokens
            )
            in_rate = max(
                int(price["input_per_mtok"]), int(price["cached_input_per_mtok"] or 0)
            )
            out_rate = max(
                int(price["output_per_mtok"]), int(price["reasoning_per_mtok"] or 0)
            )
            reserved_usd = _ceil_div(
                input_bound * in_rate + request.max_output_tokens * out_rate, _MILLION
            )
            reserved_tokens = input_bound + request.max_output_tokens
            used_usd, used_tokens = self._exposure(conn, org_id, window)
            if used_usd + reserved_usd > int(budget["limit_micro_usd"]) or (
                budget["limit_tokens"] is not None
                and used_tokens + reserved_tokens > int(budget["limit_tokens"])
            ):
                raise BudgetExceededError("Organization model budget exceeded")
            reservation_id = str(uuid4())
            stamp = now.isoformat()
            _ = conn.execute(
                """INSERT INTO model_reservations
                   (reservation_id, org_id, window_key, incident_id, task_id, run_id,
                    idempotency_key, request_fingerprint, connection_id,
                    connection_version, model, price_input, price_output,
                    price_cached_input, price_reasoning, reserved_micro_usd,
                    reserved_tokens, state, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                           'reserved', ?, ?)""",
                (
                    reservation_id,
                    org_id,
                    window,
                    request.incident_id,
                    request.task_id,
                    request.run_id,
                    request.idempotency_key,
                    fingerprint,
                    request.connection_id,
                    request.connection_version,
                    request.model,
                    price["input_per_mtok"],
                    price["output_per_mtok"],
                    price["cached_input_per_mtok"],
                    price["reasoning_per_mtok"],
                    reserved_usd,
                    reserved_tokens,
                    stamp,
                    stamp,
                ),
            )
            row = self._load(conn, org_id, reservation_id)
            self._append(
                conn,
                row,
                "reserve",
                "reserved",
                None,
                None,
                "reserved_before_io",
                actor_user_id,
                stamp,
            )
            return self._public(conn, org_id, reservation_id)

    @staticmethod
    def _set_state(
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        to_state: str,
        usage: UsageReport | None,
        cost: int | None,
        timestamp: str,
    ) -> None:
        usage = usage or UsageReport()
        tokens = (
            usage.input_tokens + usage.output_tokens
            if cost is not None
            and usage.input_tokens is not None
            and usage.output_tokens is not None
            else None
        )
        cursor = conn.execute(
            """UPDATE model_reservations SET state = ?, actual_cost_micro_usd = ?,
               actual_tokens = ?, input_tokens = COALESCE(?, input_tokens),
               output_tokens = COALESCE(?, output_tokens),
               cached_input_tokens = COALESCE(?, cached_input_tokens),
               reasoning_tokens = COALESCE(?, reasoning_tokens), updated_at = ?
               WHERE org_id = ? AND reservation_id = ? AND state = ?""",
            (
                to_state,
                cost,
                tokens,
                usage.input_tokens,
                usage.output_tokens,
                usage.cached_input_tokens,
                usage.reasoning_tokens,
                timestamp,
                row["org_id"],
                row["reservation_id"],
                row["state"],
            ),
        )
        if cursor.rowcount != 1:
            raise BudgetConflictError("Model reservation state conflict")

    def settle(
        self,
        org_id: str,
        reservation_id: str,
        usage: UsageReport,
        *,
        reason_code: str = "provider_usage",
    ) -> ModelReservation:
        """Record provider usage for a reserved attempt.

        Cost uses the reservation's price snapshot only when every billable
        component is known; otherwise the reservation becomes ``ambiguous`` and
        keeps its whole reserve as exposure. Repeating an identical settle is a
        no-op.
        """
        self._check_org(org_id)
        usage = self._validate(UsageReport, **dict(usage))
        reason_code = self._reason(reason_code)
        with self.db.transaction() as conn:
            row = self._load(conn, org_id, reservation_id)
            if row["state"] != "reserved":
                prior = conn.execute(
                    "SELECT input_tokens, output_tokens, cached_input_tokens, reasoning_tokens FROM model_usage_ledger WHERE org_id = ? AND reservation_id = ? AND action = 'settle'",
                    (org_id, reservation_id),
                ).fetchone()
                if (
                    prior is not None
                    and UsageReport(
                        input_tokens=prior["input_tokens"],
                        output_tokens=prior["output_tokens"],
                        cached_input_tokens=prior["cached_input_tokens"],
                        reasoning_tokens=prior["reasoning_tokens"],
                    )
                    == usage
                ):
                    return self._public(conn, org_id, reservation_id)
                raise BudgetConflictError(
                    "Model reservation is not open for settlement"
                )
            cost = _price_cost(
                int(row["price_input"]),
                int(row["price_output"]),
                row["price_cached_input"],
                row["price_reasoning"],
                usage,
            )
            to_state = "settled" if cost is not None else "ambiguous"
            stamp = self._now().isoformat()
            self._append(
                conn, row, "settle", to_state, usage, cost, reason_code, None, stamp
            )
            self._set_state(conn, row, to_state, usage, cost, stamp)
            return self._public(conn, org_id, reservation_id)

    def release(
        self,
        org_id: str,
        reservation_id: str,
        *,
        reason_code: str = "preflight_failure",
    ) -> ModelReservation:
        """Free a reservation whose provider call provably never started."""
        self._check_org(org_id)
        reason_code = self._reason(reason_code)
        with self.db.transaction() as conn:
            row = self._load(conn, org_id, reservation_id)
            if row["state"] == "released":
                return self._public(conn, org_id, reservation_id)
            if row["state"] != "reserved":
                raise BudgetConflictError(
                    "Only an unstarted reservation can be released"
                )
            stamp = self._now().isoformat()
            self._append(
                conn, row, "release", "released", None, 0, reason_code, None, stamp
            )
            self._set_state(conn, row, "released", None, 0, stamp)
            return self._public(conn, org_id, reservation_id)

    def mark_ambiguous(
        self,
        org_id: str,
        reservation_id: str,
        *,
        reason_code: str = "outcome_unknown",
    ) -> ModelReservation:
        """Keep the full reserve counted after a timeout, cancel or crash."""
        self._check_org(org_id)
        reason_code = self._reason(reason_code)
        with self.db.transaction() as conn:
            row = self._load(conn, org_id, reservation_id)
            if row["state"] == "ambiguous":
                return self._public(conn, org_id, reservation_id)
            if row["state"] != "reserved":
                raise BudgetConflictError("Model reservation is not open")
            stamp = self._now().isoformat()
            self._append(
                conn,
                row,
                "mark_ambiguous",
                "ambiguous",
                None,
                None,
                reason_code,
                None,
                stamp,
            )
            self._set_state(conn, row, "ambiguous", None, None, stamp)
            return self._public(conn, org_id, reservation_id)

    def recover_stale(self, org_id: str, stale_before: datetime) -> int:
        """Move reservations left ``reserved`` before a deadline to ``ambiguous``.

        Never releases: a crash after intent may have followed provider I/O.
        """
        self._check_org(org_id)
        if stale_before.tzinfo is None:
            raise BudgetValidationError("Invalid stale deadline")
        cutoff = stale_before.astimezone(UTC).isoformat()
        with self.db.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM model_reservations WHERE org_id = ? AND state = 'reserved' AND created_at < ?",
                (org_id, cutoff),
            ).fetchall()
            stamp = self._now().isoformat()
            for row in rows:
                self._append(
                    conn,
                    row,
                    "recover_stale",
                    "ambiguous",
                    None,
                    None,
                    "stale_reservation",
                    None,
                    stamp,
                )
                self._set_state(conn, row, "ambiguous", None, None, stamp)
            return len(rows)

    def reconcile(
        self,
        org_id: str,
        actor_user_id: str,
        reservation_id: str,
        *,
        usage: UsageReport | None = None,
        confirmed_no_charge: bool = False,
        reason_code: str,
    ) -> ModelReservation:
        """Admin-only resolution of an ambiguous reservation with evidence.

        Requires either fully known billable usage or an explicit
        ``confirmed_no_charge``; incomplete usage is rejected, never zeroed.
        """
        self._check_org(org_id)
        reason_code = self._reason(reason_code)
        if (usage is None) == (not confirmed_no_charge):
            raise BudgetValidationError(
                "Provide exactly one of usage or confirmed_no_charge"
            )
        checked = None if usage is None else self._validate(UsageReport, **dict(usage))
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "admin")
            row = self._load(conn, org_id, reservation_id)
            if row["state"] != "ambiguous":
                raise BudgetConflictError(
                    "Only an ambiguous reservation can be reconciled"
                )
            if checked is None:
                cost: int | None = 0
                recorded = UsageReport(input_tokens=0, output_tokens=0)
            else:
                cost = _price_cost(
                    int(row["price_input"]),
                    int(row["price_output"]),
                    row["price_cached_input"],
                    row["price_reasoning"],
                    checked,
                )
                recorded = checked
                if cost is None:
                    raise BudgetValidationError(
                        "Reconciliation usage must determine a known cost"
                    )
            stamp = self._now().isoformat()
            self._append(
                conn,
                row,
                "reconcile",
                "reconciled",
                recorded,
                cost,
                reason_code,
                actor_user_id,
                stamp,
            )
            self._set_state(conn, row, "reconciled", recorded, cost, stamp)
            return self._public(conn, org_id, reservation_id)

    # -- reads -----------------------------------------------------------------

    def get_reservation(
        self, org_id: str, actor_user_id: str, reservation_id: str
    ) -> ModelReservation:
        """Read one reservation using live membership."""
        self._check_org(org_id)
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "read")
            return self._public(conn, org_id, reservation_id)

    def list_ledger(
        self,
        org_id: str,
        actor_user_id: str,
        reservation_id: str | None = None,
        limit: int = 200,
    ) -> tuple[LedgerEntry, ...]:
        """Read ledger entries in order (bounded)."""
        self._check_org(org_id)
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise BudgetValidationError("Invalid limit")
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "read")
            if reservation_id is None:
                rows = conn.execute(
                    f"SELECT {_LEDGER_COLUMNS} FROM model_usage_ledger WHERE org_id = ? ORDER BY seq LIMIT ?",  # noqa: S608
                    (org_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT {_LEDGER_COLUMNS} FROM model_usage_ledger WHERE org_id = ? AND reservation_id = ? ORDER BY seq LIMIT ?",  # noqa: S608
                    (org_id, reservation_id, limit),
                ).fetchall()
            return tuple(self._entry(row) for row in rows)

    def usage_summary(
        self, org_id: str, actor_user_id: str, window_key: str | None = None
    ) -> UsageSummary:
        """Window totals with unknown cost and ambiguous exposure kept separate."""
        self._check_org(org_id)
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, "read")
            window = (
                window_key if window_key is not None else window_key_for(self._now())
            )
            self._check_window(window)
            totals = conn.execute(
                """SELECT
                     COALESCE(SUM(CASE WHEN state IN ('settled', 'reconciled')
                         THEN actual_cost_micro_usd END), 0) AS known,
                     COALESCE(SUM(state = 'ambiguous'), 0) AS unknown_count,
                     COALESCE(SUM(CASE WHEN state = 'ambiguous'
                         THEN reserved_micro_usd END), 0) AS ambiguous,
                     COALESCE(SUM(CASE WHEN state = 'reserved'
                         THEN reserved_micro_usd END), 0) AS reserved
                   FROM model_reservations WHERE org_id = ? AND window_key = ?""",
                (org_id, window),
            ).fetchone()
            budget = conn.execute(
                "SELECT limit_micro_usd, limit_tokens FROM model_budgets WHERE org_id = ? AND window_key = ?",
                (org_id, window),
            ).fetchone()
            known = int(totals["known"])
            ambiguous = int(totals["ambiguous"])
            reserved = int(totals["reserved"])
            exposure = known + ambiguous + reserved
            limit = None if budget is None else int(budget["limit_micro_usd"])
            return UsageSummary(
                org_id=org_id,
                window_key=window,
                limit_micro_usd=limit,
                limit_tokens=None
                if budget is None or budget["limit_tokens"] is None
                else int(budget["limit_tokens"]),
                known_cost_micro_usd=known,
                unknown_cost_count=int(totals["unknown_count"]),
                ambiguous_exposure_micro_usd=ambiguous,
                reserved_exposure_micro_usd=reserved,
                exposure_micro_usd=exposure,
                remaining_micro_usd=None if limit is None else max(0, limit - exposure),
                over_limit=limit is not None and exposure > limit,
            )


__all__ = [
    "BudgetConflictError",
    "BudgetDeniedError",
    "BudgetExceededError",
    "BudgetNotFoundError",
    "BudgetValidationError",
    "LedgerAction",
    "LedgerEntry",
    "ModelBudget",
    "ModelBudgetStore",
    "ModelPrice",
    "ModelReservation",
    "ReservationRequest",
    "ReservationState",
    "UsageReport",
    "UsageSummary",
    "window_key_for",
]
