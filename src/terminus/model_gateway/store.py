"""Durable tenant-scoped storage for named model connections."""

# pyright: reportAny=false

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, cast
from uuid import uuid4

from pydantic import SecretStr, ValidationError

from terminus.model_gateway.models import (
    ModelConnectionCreate,
    ModelConnectionUpdate,
    ModelConnectionView,
    Provider,
)
from terminus.storage.db import Database

if TYPE_CHECKING:
    from terminus.model_gateway.secrets import CredentialCipher


class _Cipher(Protocol):
    def encrypt(self, secret: str, binding: str) -> str: ...

    def decrypt(self, token: str, binding: str) -> SecretStr: ...


class ConnectionDeniedError(PermissionError):
    """The live tenant membership does not authorize the operation."""


class ConnectionNotFoundError(LookupError):
    """The tenant-scoped connection does not exist."""


class ConnectionConflictError(RuntimeError):
    """The requested mutation conflicts with durable state."""


class ConnectionValidationError(ValueError):
    """A partial update does not form a valid connection."""


class ConnectionUnavailableError(RuntimeError):
    """Credential protection is unavailable or stored material is invalid."""


_TABLES = """
CREATE TABLE IF NOT EXISTS model_connections (
    org_id TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
    provider TEXT NOT NULL,
    base_url TEXT,
    models_json TEXT NOT NULL CHECK(length(models_json) <= 6600),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    credential_ciphertext TEXT,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_model_connections_org_name
ON model_connections(org_id, lower(name));
CREATE TABLE IF NOT EXISTS model_connection_audit (
    audit_id TEXT PRIMARY KEY CHECK(length(audit_id) <= 36),
    org_id TEXT NOT NULL CHECK(length(org_id) <= 256),
    connection_id TEXT NOT NULL CHECK(length(connection_id) <= 36),
    actor_user_id TEXT NOT NULL CHECK(length(actor_user_id) <= 256),
    action TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete')),
    changed_fields_json TEXT NOT NULL CHECK(length(changed_fields_json) <= 256),
    connection_version INTEGER NOT NULL CHECK(connection_version >= 1),
    created_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS model_connection_audit_no_update
BEFORE UPDATE ON model_connection_audit
BEGIN SELECT RAISE(ABORT, 'model connection audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS model_connection_audit_no_delete
BEFORE DELETE ON model_connection_audit
BEGIN SELECT RAISE(ABORT, 'model connection audit is immutable'); END;
"""


class ModelConnectionStore:
    """Connection registry with live authorization and optimistic concurrency."""

    def __init__(self, db: Database, cipher: CredentialCipher | None) -> None:
        self.db: Database = db
        self._cipher: _Cipher | None = cast("_Cipher | None", cipher)
        with self.db.transaction() as conn:
            statement = ""
            for line in _TABLES.splitlines():
                statement += f"{line}\n"
                if sqlite3.complete_statement(statement):
                    _ = conn.execute(statement)
                    statement = ""

    @staticmethod
    def _binding(org_id: str, connection_id: str) -> str:
        return json.dumps([org_id, connection_id], separators=(",", ":"))

    @staticmethod
    def _authorize(
        conn: sqlite3.Connection, org_id: str, actor: str, *, write: bool
    ) -> None:
        row = conn.execute(
            "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, actor),
        ).fetchone()
        if row is None or (write and row["role"] != "admin"):
            raise ConnectionDeniedError("Model connection access denied")

    @staticmethod
    def _missing() -> ConnectionNotFoundError:
        return ConnectionNotFoundError("Model connection not found")

    def _validate_ciphertext(self, row: sqlite3.Row) -> None:
        token = row["credential_ciphertext"]
        if token is None or self._cipher is None:
            return
        try:
            _ = self._cipher.decrypt(
                str(token), self._binding(str(row["org_id"]), str(row["connection_id"]))
            )
        except Exception as exc:
            raise ConnectionUnavailableError(
                "Stored credential is unavailable"
            ) from exc

    def resolve_transport_credential(
        self, connection: ModelConnectionView, actor_user_id: str
    ) -> SecretStr | None:
        """Internal transport boundary: authenticate the exact registered snapshot.

        This method is never exposed by a HTTP route or included in model args.
        The AES envelope remains tenant/connection bound and failures are sanitized.
        """
        with self.db.transaction() as conn:
            self._authorize(conn, connection.org_id, actor_user_id, write=False)
            member = conn.execute(
                "SELECT role FROM memberships WHERE org_id=? AND user_id=?",
                (connection.org_id, actor_user_id),
            ).fetchone()
            if member is None or member["role"] not in {"admin", "member"}:
                raise ConnectionDeniedError("Model transport credential access denied")
            row = conn.execute(
                "SELECT * FROM model_connections WHERE org_id=? AND connection_id=?",
                (connection.org_id, connection.connection_id),
            ).fetchone()
            if row is None or not connection.enabled or self._view(row) != connection:
                raise ConnectionUnavailableError("Model connection changed")
            token = row["credential_ciphertext"]
            if token is None:
                if connection.provider == "local":
                    return None
                raise ConnectionUnavailableError("Model credential is unavailable")
            if self._cipher is None:
                raise ConnectionUnavailableError("Model credential is unavailable")
            try:
                return self._cipher.decrypt(
                    str(token),
                    self._binding(connection.org_id, connection.connection_id),
                )
            except Exception:
                raise ConnectionUnavailableError(
                    "Model credential is unavailable"
                ) from None

    @staticmethod
    def _validate_create_request(
        request: ModelConnectionCreate,
    ) -> ModelConnectionCreate:
        try:
            payload = request.model_dump(warnings=False)
            payload["api_key"] = request.api_key
            return ModelConnectionCreate.model_validate(payload)
        except (AttributeError, TypeError, ValidationError) as exc:
            raise ConnectionValidationError("Invalid model connection") from exc

    @staticmethod
    def _validate_update_request(
        request: ModelConnectionUpdate,
    ) -> ModelConnectionUpdate:
        try:
            supplied = request.model_fields_set
            payload = request.model_dump(exclude_unset=True, warnings=False)
            if "api_key" in supplied:
                payload["api_key"] = request.api_key
            return ModelConnectionUpdate.model_validate(payload)
        except (AttributeError, TypeError, ValidationError) as exc:
            raise ConnectionValidationError("Invalid model connection update") from exc

    def _view(self, row: sqlite3.Row) -> ModelConnectionView:
        self._validate_ciphertext(row)
        configured = row["credential_ciphertext"] is not None
        try:
            models = json.loads(str(row["models_json"]))
            return ModelConnectionView(
                org_id=str(row["org_id"]),
                connection_id=str(row["connection_id"]),
                name=str(row["name"]),
                provider=cast("Provider", row["provider"]),
                base_url=None if row["base_url"] is None else str(row["base_url"]),
                models=models,
                enabled=bool(row["enabled"]),
                credential_configured=configured,
                credential_mask="********" if configured else None,
                version=int(row["version"]),
                created_at=datetime.fromisoformat(str(row["created_at"])),
                updated_at=datetime.fromisoformat(str(row["updated_at"])),
            )
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            raise ConnectionUnavailableError(
                "Stored model connection is unavailable"
            ) from exc

    @staticmethod
    def _audit(
        conn: sqlite3.Connection,
        org_id: str,
        connection_id: str,
        actor: str,
        action: str,
        fields: set[str],
        version: int,
        timestamp: str,
    ) -> None:
        safe_fields = sorted(
            "credential" if item == "api_key" else item for item in fields
        )
        _ = conn.execute(
            """INSERT INTO model_connection_audit
               (audit_id, org_id, connection_id, actor_user_id, action,
                changed_fields_json, connection_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid4()),
                org_id,
                connection_id,
                actor,
                action,
                json.dumps(safe_fields, separators=(",", ":")),
                version,
                timestamp,
            ),
        )

    def create(
        self, org_id: str, actor_user_id: str, request: ModelConnectionCreate
    ) -> ModelConnectionView:
        connection_id = str(uuid4())
        timestamp = datetime.now(UTC).isoformat()
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=True)
            request = self._validate_create_request(request)
            credential: str | None = None
            if request.api_key is not None:
                if self._cipher is None:
                    raise ConnectionUnavailableError(
                        "Credential encryption is unavailable"
                    )
                try:
                    credential = self._cipher.encrypt(
                        request.api_key.get_secret_value(),
                        self._binding(org_id, connection_id),
                    )
                except Exception as exc:
                    raise ConnectionUnavailableError(
                        "Credential encryption failed"
                    ) from exc
            count = conn.execute(
                "SELECT count(*) FROM model_connections WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            if count >= 50:
                raise ConnectionConflictError("Model connection limit reached")
            try:
                _ = conn.execute(
                    """INSERT INTO model_connections
                       (org_id, connection_id, name, provider, base_url, models_json,
                        enabled, credential_ciphertext, version, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                    (
                        org_id,
                        connection_id,
                        request.name,
                        request.provider,
                        request.base_url,
                        json.dumps(request.models, separators=(",", ":")),
                        int(request.enabled),
                        credential,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "ux_model_connections_org_name" in str(
                    exc
                ) or "model_connections.org_id, model_connections.name" in str(exc):
                    raise ConnectionConflictError(
                        "A connection with this name already exists"
                    ) from exc
                raise
            self._audit(
                conn,
                org_id,
                connection_id,
                actor_user_id,
                "create",
                set(request.model_fields_set),
                1,
                timestamp,
            )
            row = conn.execute(
                "SELECT * FROM model_connections WHERE org_id = ? AND connection_id = ?",
                (org_id, connection_id),
            ).fetchone()
            if row is None:  # pragma: no cover - same-transaction invariant
                raise ConnectionUnavailableError(
                    "Stored model connection is unavailable"
                )
            return self._view(row)

    def list_for_org(
        self, org_id: str, actor_user_id: str
    ) -> list[ModelConnectionView]:
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=False)
            rows = conn.execute(
                """SELECT * FROM model_connections WHERE org_id = ?
                   ORDER BY lower(name), connection_id""",
                (org_id,),
            ).fetchall()
            return [self._view(row) for row in rows]

    def get(
        self, org_id: str, actor_user_id: str, connection_id: str
    ) -> ModelConnectionView:
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=False)
            row = conn.execute(
                "SELECT * FROM model_connections WHERE org_id = ? AND connection_id = ?",
                (org_id, connection_id),
            ).fetchone()
            if row is None:
                raise self._missing()
            return self._view(row)

    def update(  # noqa: C901, PLR0912, PLR0915 - atomic patch semantics stay together
        self,
        org_id: str,
        actor_user_id: str,
        connection_id: str,
        request: ModelConnectionUpdate,
    ) -> ModelConnectionView:
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=True)
            request = self._validate_update_request(request)
            row = conn.execute(
                "SELECT * FROM model_connections WHERE org_id = ? AND connection_id = ?",
                (org_id, connection_id),
            ).fetchone()
            if row is None:
                raise self._missing()
            self._validate_ciphertext(row)
            if int(row["version"]) != request.expected_version:
                raise ConnectionConflictError("Model connection version conflict")

            supplied = request.model_fields_set
            provider = (
                request.provider if "provider" in supplied else str(row["provider"])
            )
            if (
                "provider" in supplied
                and provider != row["provider"]
                and row["credential_ciphertext"] is not None
                and "api_key" not in supplied
            ):
                raise ConnectionConflictError(
                    "Changing provider requires replacing or clearing the credential"
                )
            if (
                "base_url" in supplied
                and request.base_url != row["base_url"]
                and row["credential_ciphertext"] is not None
                and "api_key" not in supplied
            ):
                raise ConnectionConflictError(
                    "Changing endpoint requires replacing or clearing the credential"
                )
            if "base_url" in supplied:
                base_url = request.base_url
            elif "provider" in supplied and provider != row["provider"]:
                base_url = None
            else:
                base_url = None if row["base_url"] is None else str(row["base_url"])
            try:
                stored_models = json.loads(str(row["models_json"]))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ConnectionUnavailableError(
                    "Stored model connection is unavailable"
                ) from exc
            try:
                candidate = ModelConnectionCreate.model_validate(
                    {
                        "name": request.name
                        if "name" in supplied
                        else str(row["name"]),
                        "provider": provider,
                        "base_url": base_url,
                        "models": request.models
                        if "models" in supplied
                        else stored_models,
                        "enabled": request.enabled
                        if "enabled" in supplied
                        else bool(row["enabled"]),
                    }
                )
            except ValidationError as exc:
                raise ConnectionValidationError(
                    "Invalid model connection update"
                ) from exc
            credential = row["credential_ciphertext"]
            if "api_key" in supplied:
                if request.api_key is None:
                    credential = None
                else:
                    if self._cipher is None:
                        raise ConnectionUnavailableError(
                            "Credential encryption is unavailable"
                        )
                    try:
                        credential = self._cipher.encrypt(
                            request.api_key.get_secret_value(),
                            self._binding(org_id, connection_id),
                        )
                    except Exception as exc:
                        raise ConnectionUnavailableError(
                            "Credential encryption failed"
                        ) from exc
            timestamp = datetime.now(UTC).isoformat()
            next_version = request.expected_version + 1
            try:
                cursor = conn.execute(
                    """UPDATE model_connections
                       SET name = ?, provider = ?, base_url = ?, models_json = ?,
                           enabled = ?, credential_ciphertext = ?, version = ?, updated_at = ?
                       WHERE org_id = ? AND connection_id = ? AND version = ?""",
                    (
                        candidate.name,
                        candidate.provider,
                        candidate.base_url,
                        json.dumps(candidate.models, separators=(",", ":")),
                        int(candidate.enabled),
                        credential,
                        next_version,
                        timestamp,
                        org_id,
                        connection_id,
                        request.expected_version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "ux_model_connections_org_name" in str(
                    exc
                ) or "model_connections.org_id, model_connections.name" in str(exc):
                    raise ConnectionConflictError(
                        "A connection with this name already exists"
                    ) from exc
                raise
            if cursor.rowcount != 1:
                raise ConnectionConflictError("Model connection version conflict")
            changed = set(supplied) - {"expected_version"}
            self._audit(
                conn,
                org_id,
                connection_id,
                actor_user_id,
                "update",
                changed,
                next_version,
                timestamp,
            )
            updated = conn.execute(
                "SELECT * FROM model_connections WHERE org_id = ? AND connection_id = ?",
                (org_id, connection_id),
            ).fetchone()
            if updated is None:  # pragma: no cover - same-transaction invariant
                raise ConnectionUnavailableError(
                    "Stored model connection is unavailable"
                )
            return self._view(updated)

    def delete(
        self,
        org_id: str,
        actor_user_id: str,
        connection_id: str,
        expected_version: int,
    ) -> None:
        unchecked_version: object = expected_version
        if type(unchecked_version) is not int:
            raise ConnectionValidationError("Invalid expected version")
        if expected_version < 1:
            raise ValueError("expected_version must be at least 1")
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=True)
            row = conn.execute(
                "SELECT * FROM model_connections WHERE org_id = ? AND connection_id = ?",
                (org_id, connection_id),
            ).fetchone()
            if row is None:
                raise self._missing()
            self._validate_ciphertext(row)
            if int(row["version"]) != expected_version:
                raise ConnectionConflictError("Model connection version conflict")
            cursor = conn.execute(
                """DELETE FROM model_connections
                   WHERE org_id = ? AND connection_id = ? AND version = ?""",
                (org_id, connection_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise ConnectionConflictError("Model connection version conflict")
            timestamp = datetime.now(UTC).isoformat()
            self._audit(
                conn,
                org_id,
                connection_id,
                actor_user_id,
                "delete",
                set(),
                expected_version,
                timestamp,
            )
