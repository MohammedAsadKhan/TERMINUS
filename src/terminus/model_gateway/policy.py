"""Durable tenant policy for model access and evidence data handling."""

# pyright: reportAny=false

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from typing import Annotated, ClassVar, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from terminus.orchestration.models import EvidenceRecord
from terminus.storage.db import Database
from terminus.toolkit.catalog import CORE_ROLES

Area = Literal[
    "alert_handling",
    "investigation",
    "infrastructure",
    "applications_data",
    "response_improvement",
]
DataClassification = Literal["local_only", "approved_cloud", "redacted_cloud"]

_ROLES = CORE_ROLES | {"main_orchestrator", "area_orchestrator"}
_MODEL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$"
_MODEL_ID = re.compile(_MODEL_PATTERN)
_IDENTIFIER = r"\S"
_MODEL_POOL = TypeAdapter(list[str])


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )


class PolicyGrant(_Contract):
    """Models and evidence classes one durable agent role may use."""

    role: Annotated[str, Field(min_length=1, max_length=120, pattern=_IDENTIFIER)]
    area: Area | None = None
    connection_id: Annotated[
        str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER)
    ]
    connection_version: Annotated[int, Field(ge=1)]
    models: Annotated[
        tuple[Annotated[str, Field(pattern=_MODEL_PATTERN)], ...],
        Field(min_length=1, max_length=50),
    ]
    classifications: Annotated[
        tuple[DataClassification, ...], Field(min_length=1, max_length=3)
    ] = ("redacted_cloud",)

    @model_validator(mode="after")
    def validate_scope(self) -> PolicyGrant:
        if self.role not in _ROLES:
            raise ValueError("role is not eligible for model access")
        if self.role == "area_orchestrator":
            if self.area is None:
                raise ValueError("area_orchestrator grants require an area")
        elif self.area is not None:
            raise ValueError("only area_orchestrator grants may specify an area")
        if len(set(self.models)) != len(self.models):
            raise ValueError("model identifiers must be unique")
        if len(set(self.classifications)) != len(self.classifications):
            raise ValueError("classifications must be unique")
        return self


class ModelPolicyWrite(_Contract):
    """Compare-and-swap replacement of an organization's complete model policy."""

    expected_version: Annotated[int, Field(ge=0)] = 0
    grants: Annotated[tuple[PolicyGrant, ...], Field(max_length=100)]
    enabled: bool = True

    @model_validator(mode="after")
    def unique_grants(self) -> ModelPolicyWrite:
        identities = [
            (grant.role, grant.area, grant.connection_id) for grant in self.grants
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("policy grants must be unique by role, area, and connection")
        return self


class ModelPolicy(_Contract):
    """Current durable model policy for one organization."""

    org_id: Annotated[str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER)]
    version: Annotated[int, Field(ge=1)]
    grants: Annotated[tuple[PolicyGrant, ...], Field(max_length=100)]
    enabled: bool

    @model_validator(mode="after")
    def unique_grants(self) -> ModelPolicy:
        identities = [
            (grant.role, grant.area, grant.connection_id) for grant in self.grants
        ]
        if len(set(identities)) != len(identities):
            raise ValueError("policy grants must be unique by role, area, and connection")
        return self


class EvidenceClassification(_Contract):
    """Versioned data-handling label bound to canonical immutable evidence."""

    org_id: Annotated[str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER)]
    evidence_id: Annotated[
        str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER)
    ]
    content_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    classification: DataClassification
    version: Annotated[int, Field(ge=1)]


class ModelPolicyDeniedError(ValueError):
    """The live tenant membership does not authorize the operation."""


class ModelPolicyConflictError(ValueError):
    """The requested write conflicts with current durable state."""


class ModelPolicyNotFoundError(LookupError):
    """A tenant-scoped policy resource does not exist."""


class ModelPolicyValidationError(ValueError):
    """A request or referenced durable record is invalid."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS model_policies (
    org_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK(version >= 1),
    grants_json TEXT NOT NULL CHECK(length(grants_json) <= 1048576),
    enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
    updated_at TEXT NOT NULL,
    FOREIGN KEY(org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS model_evidence_classifications (
    org_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    content_hash TEXT NOT NULL CHECK(
        length(content_hash) = 64 AND content_hash NOT GLOB '*[^0-9a-f]*'
    ),
    classification TEXT NOT NULL CHECK(classification IN
        ('local_only', 'approved_cloud', 'redacted_cloud')),
    version INTEGER NOT NULL CHECK(version >= 1),
    updated_at TEXT NOT NULL,
    PRIMARY KEY(org_id, evidence_id),
    FOREIGN KEY(org_id, evidence_id)
        REFERENCES orchestration_evidence(org_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS model_policy_audit (
    audit_id TEXT PRIMARY KEY CHECK(length(audit_id) <= 36),
    org_id TEXT NOT NULL CHECK(length(org_id) <= 200),
    actor_user_id TEXT NOT NULL CHECK(length(actor_user_id) <= 200),
    action TEXT NOT NULL CHECK(action IN ('put_policy', 'classify_evidence')),
    subject_id TEXT NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 200),
    subject_version INTEGER NOT NULL CHECK(subject_version >= 1),
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_model_policy_audit_org
ON model_policy_audit(org_id, created_at, audit_id);
CREATE TRIGGER IF NOT EXISTS model_policy_audit_no_update
BEFORE UPDATE ON model_policy_audit
BEGIN SELECT RAISE(ABORT, 'model policy audit is immutable'); END;
CREATE TRIGGER IF NOT EXISTS model_policy_audit_no_delete
BEFORE DELETE ON model_policy_audit
BEGIN SELECT RAISE(ABORT, 'model policy audit is immutable'); END;
"""


class ModelPolicyStore:
    """Tenant-scoped policy storage with live authorization and CAS writes."""

    def __init__(self, db: Database) -> None:
        self.db: Database = db
        with self.db.transaction() as conn:
            statement = ""
            for line in _SCHEMA.splitlines():
                statement += f"{line}\n"
                if sqlite3.complete_statement(statement):
                    _ = conn.execute(statement)
                    statement = ""

    @staticmethod
    def _authorize(
        conn: sqlite3.Connection,
        org_id: str,
        actor_user_id: str,
        *,
        write: bool,
    ) -> None:
        row = conn.execute(
            "SELECT role FROM memberships WHERE org_id = ? AND user_id = ?",
            (org_id, actor_user_id),
        ).fetchone()
        if row is None or (write and row["role"] != "admin"):
            raise ModelPolicyDeniedError("Model policy access denied")

    @staticmethod
    def _missing() -> ModelPolicyNotFoundError:
        return ModelPolicyNotFoundError("Model policy resource not found")

    @staticmethod
    def _validate_write(request: ModelPolicyWrite) -> ModelPolicyWrite:
        try:
            return ModelPolicyWrite.model_validate(request.model_dump(warnings=False))
        except (AttributeError, TypeError, ValidationError) as exc:
            raise ModelPolicyValidationError("Invalid model policy") from exc

    @staticmethod
    def _policy(row: sqlite3.Row) -> ModelPolicy:
        try:
            payload = json.dumps(
                {
                    "org_id": row["org_id"],
                    "version": row["version"],
                    "grants": json.loads(str(row["grants_json"])),
                    "enabled": bool(row["enabled"]),
                },
                separators=(",", ":"),
            )
            return ModelPolicy.model_validate_json(payload)
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError) as exc:
            raise ModelPolicyValidationError("Stored model policy is invalid") from exc

    @staticmethod
    def _classification(row: sqlite3.Row) -> EvidenceClassification:
        try:
            return EvidenceClassification.model_validate(
                {
                    "org_id": str(row["org_id"]),
                    "evidence_id": str(row["evidence_id"]),
                    "content_hash": str(row["content_hash"]),
                    "classification": str(row["classification"]),
                    "version": int(row["version"]),
                }
            )
        except (TypeError, ValueError, ValidationError) as exc:
            raise ModelPolicyValidationError(
                "Stored evidence classification is invalid"
            ) from exc

    @staticmethod
    def _canonical_evidence(
        conn: sqlite3.Connection, org_id: str, evidence_id: str
    ) -> EvidenceRecord:
        row = conn.execute(
            """SELECT payload_json FROM orchestration_evidence
               WHERE org_id = ? AND evidence_id = ?""",
            (org_id, evidence_id),
        ).fetchone()
        if row is None:
            raise ModelPolicyStore._missing()
        try:
            evidence = EvidenceRecord.model_validate_json(str(row["payload_json"]))
        except (TypeError, ValueError, ValidationError) as exc:
            raise ModelPolicyValidationError("Canonical evidence is invalid") from exc
        if evidence.org_id != org_id or evidence.evidence_id != evidence_id:
            raise ModelPolicyValidationError("Canonical evidence identity is invalid")
        return evidence

    @staticmethod
    def _validate_connections(
        conn: sqlite3.Connection, org_id: str, grants: tuple[PolicyGrant, ...]
    ) -> None:
        cached: dict[str, tuple[int, frozenset[str]]] = {}
        for grant in grants:
            metadata = cached.get(grant.connection_id)
            if metadata is None:
                row = conn.execute(
                    """SELECT version, models_json FROM model_connections
                       WHERE org_id = ? AND connection_id = ?""",
                    (org_id, grant.connection_id),
                ).fetchone()
                if row is None:
                    raise ModelPolicyValidationError(
                        "Policy references an unavailable model connection"
                    )
                try:
                    raw_models = _MODEL_POOL.validate_json(
                        str(row["models_json"]), strict=True
                    )
                    if (
                        not 1 <= len(raw_models) <= 50
                        or len(set(raw_models)) != len(raw_models)
                        or any(not _MODEL_ID.fullmatch(item) for item in raw_models)
                    ):
                        raise ValueError
                    metadata = (int(row["version"]), frozenset(raw_models))
                except (TypeError, ValueError, ValidationError) as exc:
                    raise ModelPolicyValidationError(
                        "Referenced model connection metadata is invalid"
                    ) from exc
                cached[grant.connection_id] = metadata
            version, model_pool = metadata
            if version != grant.connection_version:
                raise ModelPolicyConflictError("Model connection version conflict")
            if not set(grant.models) <= model_pool:
                raise ModelPolicyValidationError(
                    "Policy models must be present in the connection model pool"
                )

    @staticmethod
    def _audit(
        conn: sqlite3.Connection,
        org_id: str,
        actor_user_id: str,
        action: Literal["put_policy", "classify_evidence"],
        subject_id: str,
        version: int,
        timestamp: str,
    ) -> None:
        _ = conn.execute(
            """INSERT INTO model_policy_audit
               (audit_id, org_id, actor_user_id, action, subject_id,
                subject_version, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                str(uuid4()),
                org_id,
                actor_user_id,
                action,
                subject_id,
                version,
                timestamp,
            ),
        )

    def put(
        self, org_id: str, actor_user_id: str, request: ModelPolicyWrite
    ) -> ModelPolicy:
        """Replace the complete policy after validating its durable dependencies."""
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=True)
            request = self._validate_write(request)
            current = conn.execute(
                "SELECT version FROM model_policies WHERE org_id = ?", (org_id,)
            ).fetchone()
            current_version = 0 if current is None else int(current["version"])
            if current_version != request.expected_version:
                raise ModelPolicyConflictError("Model policy version conflict")
            self._validate_connections(conn, org_id, request.grants)

            next_version = current_version + 1
            grants_json = json.dumps(
                [grant.model_dump(mode="json") for grant in request.grants],
                sort_keys=True,
                separators=(",", ":"),
            )
            timestamp = datetime.now(UTC).isoformat()
            if current is None:
                _ = conn.execute(
                    """INSERT INTO model_policies
                       (org_id, version, grants_json, enabled, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (org_id, next_version, grants_json, int(request.enabled), timestamp),
                )
            else:
                cursor = conn.execute(
                    """UPDATE model_policies
                       SET version = ?, grants_json = ?, enabled = ?, updated_at = ?
                       WHERE org_id = ? AND version = ?""",
                    (
                        next_version,
                        grants_json,
                        int(request.enabled),
                        timestamp,
                        org_id,
                        request.expected_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ModelPolicyConflictError("Model policy version conflict")
            self._audit(
                conn,
                org_id,
                actor_user_id,
                "put_policy",
                org_id,
                next_version,
                timestamp,
            )
            return ModelPolicy(
                org_id=org_id,
                version=next_version,
                grants=request.grants,
                enabled=request.enabled,
            )

    def get(self, org_id: str, actor_user_id: str) -> ModelPolicy:
        """Read the current policy using live organization membership."""
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=False)
            row = conn.execute(
                "SELECT org_id, version, grants_json, enabled FROM model_policies WHERE org_id = ?",
                (org_id,),
            ).fetchone()
            if row is None:
                raise self._missing()
            return self._policy(row)

    def classify_evidence(
        self,
        org_id: str,
        actor_user_id: str,
        evidence_id: str,
        classification: DataClassification,
        expected_version: int = 0,
    ) -> EvidenceClassification:
        """Create or replace a classification bound to canonical evidence metadata."""
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=True)
            if type(expected_version) is not int or expected_version < 0:
                raise ModelPolicyValidationError(
                    "Invalid expected classification version"
                )
            try:
                checked = EvidenceClassification.model_validate(
                    {
                        "org_id": org_id,
                        "evidence_id": evidence_id,
                        "content_hash": "0" * 64,
                        "classification": classification,
                        "version": 1,
                    }
                )
            except (TypeError, ValueError, ValidationError) as exc:
                raise ModelPolicyValidationError(
                    "Invalid evidence classification"
                ) from exc
            evidence = self._canonical_evidence(conn, org_id, evidence_id)
            current = conn.execute(
                """SELECT version, content_hash
                   FROM model_evidence_classifications
                   WHERE org_id = ? AND evidence_id = ?""",
                (org_id, evidence_id),
            ).fetchone()
            current_version = 0 if current is None else int(current["version"])
            if current_version != expected_version:
                raise ModelPolicyConflictError(
                    "Evidence classification version conflict"
                )
            if current is not None and str(current["content_hash"]) != evidence.content_hash:
                raise ModelPolicyValidationError(
                    "Evidence classification does not match canonical evidence"
                )

            next_version = current_version + 1
            timestamp = datetime.now(UTC).isoformat()
            if current is None:
                _ = conn.execute(
                    """INSERT INTO model_evidence_classifications
                       (org_id, evidence_id, content_hash, classification, version,
                        updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        org_id,
                        evidence_id,
                        evidence.content_hash,
                        checked.classification,
                        next_version,
                        timestamp,
                    ),
                )
            else:
                cursor = conn.execute(
                    """UPDATE model_evidence_classifications
                       SET classification = ?, version = ?, updated_at = ?
                       WHERE org_id = ? AND evidence_id = ? AND version = ?
                           AND content_hash = ?""",
                    (
                        checked.classification,
                        next_version,
                        timestamp,
                        org_id,
                        evidence_id,
                        expected_version,
                        evidence.content_hash,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ModelPolicyConflictError(
                        "Evidence classification version conflict"
                    )
            self._audit(
                conn,
                org_id,
                actor_user_id,
                "classify_evidence",
                evidence_id,
                next_version,
                timestamp,
            )
            return EvidenceClassification(
                org_id=org_id,
                evidence_id=evidence_id,
                content_hash=evidence.content_hash,
                classification=checked.classification,
                version=next_version,
            )

    def get_classification(
        self, org_id: str, actor_user_id: str, evidence_id: str
    ) -> EvidenceClassification | None:
        """Read a classification and verify its canonical evidence binding."""
        with self.db.transaction() as conn:
            self._authorize(conn, org_id, actor_user_id, write=False)
            row = conn.execute(
                """SELECT org_id, evidence_id, content_hash, classification, version
                   FROM model_evidence_classifications
                   WHERE org_id = ? AND evidence_id = ?""",
                (org_id, evidence_id),
            ).fetchone()
            if row is None:
                return None
            record = self._classification(row)
            evidence = self._canonical_evidence(conn, org_id, evidence_id)
            if record.content_hash != evidence.content_hash:
                raise ModelPolicyValidationError(
                    "Evidence classification does not match canonical evidence"
                )
            return record


__all__ = [
    "Area",
    "DataClassification",
    "EvidenceClassification",
    "ModelPolicy",
    "ModelPolicyConflictError",
    "ModelPolicyDeniedError",
    "ModelPolicyNotFoundError",
    "ModelPolicyStore",
    "ModelPolicyValidationError",
    "ModelPolicyWrite",
    "PolicyGrant",
]
