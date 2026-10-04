"""Durable role, model, and evidence-classification policy checks."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from terminus.model_gateway.models import ModelConnectionCreate, ModelConnectionUpdate
from terminus.model_gateway.policy import (
    EvidenceClassification,
    ModelPolicyConflictError,
    ModelPolicyDeniedError,
    ModelPolicyNotFoundError,
    ModelPolicyStore,
    ModelPolicyValidationError,
    ModelPolicyWrite,
    PolicyGrant,
)
from terminus.model_gateway.store import ModelConnectionStore
from terminus.orchestration.storage import OrchestrationStore
from terminus.storage.db import Database
from terminus.toolkit.catalog import CORE_ROLES


def _identity(db: Database, org_id: str, user_id: str, role: str) -> None:
    db.execute(
        """INSERT OR IGNORE INTO users
           (user_id, email, password_hash, display_name, created_at)
           VALUES (?, ?, 'hash', ?, '2026-01-01T00:00:00+00:00')""",
        (user_id, f"{user_id}@example.test", user_id),
    )
    db.execute(
        """INSERT OR IGNORE INTO organizations (org_id, name, created_at)
           VALUES (?, ?, '2026-01-01T00:00:00+00:00')""",
        (org_id, org_id),
    )
    db.execute(
        "INSERT INTO memberships (org_id, user_id, role) VALUES (?, ?, ?)",
        (org_id, user_id, role),
    )


@pytest.fixture
def policy_registry(tmp_path: Path):
    db = Database(str(tmp_path / "policy.sqlite"))
    _identity(db, "alpha", "admin", "admin")
    _identity(db, "alpha", "member", "member")
    _identity(db, "bravo", "other-admin", "admin")
    connections = ModelConnectionStore(db, None)
    connection = connections.create(
        "alpha",
        "admin",
        ModelConnectionCreate(
            name="Private Models",
            provider="local",
            base_url="http://127.0.0.1:11434/v1",
            models=["small", "large"],
            enabled=False,
        ),
    )
    records = OrchestrationStore(db)
    task = records.create_task(
        "alpha", "incident-1", "investigation", "triage", "Investigate"
    )
    evidence = records.create_evidence(
        "alpha",
        task.task_id,
        "siem",
        datetime.now(UTC),
        content={"marker": "payload-must-not-enter-policy-audit"},
    )
    return db, connections, connection, evidence, ModelPolicyStore(db)


def _grant(connection_id: str, connection_version: int = 1, **changes) -> PolicyGrant:
    values = {
        "role": "triage",
        "connection_id": connection_id,
        "connection_version": connection_version,
        "models": ("small",),
    }
    values.update(changes)
    return PolicyGrant(**values)


def test_contracts_are_strict_and_roles_and_areas_are_closed() -> None:
    roles = CORE_ROLES | {"main_orchestrator"}
    for role in roles:
        assert _grant("connection", role=role).area is None
    area = _grant(
        "connection",
        role="area_orchestrator",
        area="investigation",
        classifications=("local_only", "redacted_cloud"),
    )
    assert area.area == "investigation"
    assert area.classifications == ("local_only", "redacted_cloud")

    for values in (
        {"role": "future_role"},
        {"role": "triage", "area": "investigation"},
        {"role": "area_orchestrator"},
        {"models": ("small", "small")},
        {"models": ()},
        {"classifications": ("local_only", "local_only")},
    ):
        with pytest.raises(ValidationError):
            _grant("connection", **values)
    with pytest.raises(ValidationError):
        PolicyGrant(
            role="triage",
            connection_id="connection",
            connection_version=True,
            models=["small"],
        )
    with pytest.raises(ValidationError):
        ModelPolicyWrite(
            grants=(
                _grant("connection", models=("small",)),
                _grant("connection", models=("large",)),
            )
        )


def test_policy_write_reads_restarts_and_uses_cas(policy_registry) -> None:
    db, _, connection, _, store = policy_registry
    request = ModelPolicyWrite(grants=(_grant(connection.connection_id),))
    created = store.put("alpha", "admin", request)
    assert created.version == 1
    assert created.enabled is True
    assert store.get("alpha", "member") == created

    reopened = ModelPolicyStore(Database(db.db_path))
    assert reopened.get("alpha", "member") == created
    updated = reopened.put(
        "alpha",
        "admin",
        ModelPolicyWrite(expected_version=1, grants=created.grants, enabled=False),
    )
    assert updated.version == 2
    assert updated.enabled is False
    with pytest.raises(ModelPolicyConflictError):
        store.put("alpha", "admin", request)


def test_membership_and_admin_authorization_is_live(policy_registry) -> None:
    db, _, connection, evidence, store = policy_registry
    request = ModelPolicyWrite(grants=(_grant(connection.connection_id),))
    with pytest.raises(ModelPolicyDeniedError):
        store.put("alpha", "member", request)
    with pytest.raises(ModelPolicyDeniedError):
        store.get("alpha", "other-admin")
    with pytest.raises(ModelPolicyNotFoundError) as absent:
        store.get("bravo", "other-admin")
    assert str(absent.value) == "Model policy resource not found"

    _ = store.put("alpha", "admin", request)
    db.execute(
        "UPDATE memberships SET role='member' WHERE org_id='alpha' AND user_id='admin'"
    )
    with pytest.raises(ModelPolicyDeniedError):
        store.put(
            "alpha",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=request.grants),
        )
    with pytest.raises(ModelPolicyDeniedError):
        store.classify_evidence(
            "alpha", "admin", evidence.evidence_id, "local_only"
        )


def test_policy_validates_exact_connection_version_and_model_pool(
    policy_registry,
) -> None:
    _, connections, connection, _, store = policy_registry
    for grant, error in (
        (_grant("missing"), ModelPolicyValidationError),
        (_grant(connection.connection_id, 2), ModelPolicyConflictError),
        (
            _grant(connection.connection_id, models=("unregistered",)),
            ModelPolicyValidationError,
        ),
    ):
        with pytest.raises(error):
            store.put("alpha", "admin", ModelPolicyWrite(grants=(grant,)))

    # Policy registration uses metadata only: disabled connections without credentials
    # are valid, but any connection metadata version change invalidates stale grants.
    created = store.put(
        "alpha",
        "admin",
        ModelPolicyWrite(grants=(_grant(connection.connection_id),)),
    )
    assert created.grants[0].models == ("small",)
    _ = connections.update(
        "alpha",
        "admin",
        connection.connection_id,
        ModelConnectionUpdate(expected_version=1, models=["small", "large", "new"]),
    )
    with pytest.raises(ModelPolicyConflictError):
        store.put(
            "alpha",
            "admin",
            ModelPolicyWrite(expected_version=1, grants=created.grants),
        )


def test_store_revalidates_constructed_nested_requests(policy_registry) -> None:
    _, _, connection, _, store = policy_registry
    hostile_grant = PolicyGrant.model_construct(
        role="future_role",
        area=None,
        connection_id=connection.connection_id,
        connection_version=1,
        models=("small",),
        classifications=("redacted_cloud",),
    )
    hostile = ModelPolicyWrite.model_construct(
        expected_version=0, grants=(hostile_grant,), enabled=True
    )
    with pytest.raises(ModelPolicyValidationError):
        store.put("alpha", "admin", hostile)
    with pytest.raises(ModelPolicyNotFoundError):
        store.get("alpha", "admin")


def test_evidence_classification_is_canonical_versioned_and_tenant_scoped(
    policy_registry,
) -> None:
    db, _, _, evidence, store = policy_registry
    assert store.get_classification("alpha", "member", evidence.evidence_id) is None
    first = store.classify_evidence(
        "alpha", "admin", evidence.evidence_id, "local_only"
    )
    assert first == EvidenceClassification(
        org_id="alpha",
        evidence_id=evidence.evidence_id,
        content_hash=evidence.content_hash,
        classification="local_only",
        version=1,
    )
    assert store.get_classification("alpha", "member", evidence.evidence_id) == first

    reopened = ModelPolicyStore(Database(db.db_path))
    second = reopened.classify_evidence(
        "alpha",
        "admin",
        evidence.evidence_id,
        "approved_cloud",
        expected_version=1,
    )
    assert second.version == 2
    with pytest.raises(ModelPolicyConflictError):
        store.classify_evidence(
            "alpha",
            "admin",
            evidence.evidence_id,
            "redacted_cloud",
            expected_version=1,
        )
    with pytest.raises(ModelPolicyNotFoundError) as cross_tenant:
        store.classify_evidence(
            "bravo", "other-admin", evidence.evidence_id, "local_only"
        )
    with pytest.raises(ModelPolicyNotFoundError) as missing:
        store.classify_evidence("bravo", "other-admin", "missing", "local_only")
    assert str(cross_tenant.value) == str(missing.value)


def test_classification_boundary_and_hash_binding(policy_registry) -> None:
    db, _, _, evidence, store = policy_registry
    for classification, version in (("future", 0), ("local_only", True)):
        with pytest.raises(ModelPolicyValidationError):
            store.classify_evidence(
                "alpha",
                "admin",
                evidence.evidence_id,
                classification,
                expected_version=version,
            )
    _ = store.classify_evidence(
        "alpha", "admin", evidence.evidence_id, "redacted_cloud"
    )
    db.execute(
        """UPDATE model_evidence_classifications SET content_hash = ?
           WHERE org_id = ? AND evidence_id = ?""",
        ("0" * 64, "alpha", evidence.evidence_id),
    )
    with pytest.raises(ModelPolicyValidationError, match="canonical evidence"):
        store.get_classification("alpha", "member", evidence.evidence_id)


def test_concurrent_policy_writers_have_one_cas_winner(policy_registry) -> None:
    _, _, connection, _, store = policy_registry
    initial = store.put(
        "alpha",
        "admin",
        ModelPolicyWrite(grants=(_grant(connection.connection_id),)),
    )

    def update(enabled: bool) -> bool:
        try:
            store.put(
                "alpha",
                "admin",
                ModelPolicyWrite(
                    expected_version=initial.version,
                    grants=initial.grants,
                    enabled=enabled,
                ),
            )
        except ModelPolicyConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(update, (True, False)))
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    assert store.get("alpha", "member").version == 2


def test_audit_is_immutable_minimal_and_transactional(policy_registry) -> None:
    db, _, connection, evidence, store = policy_registry
    _ = store.put(
        "alpha",
        "admin",
        ModelPolicyWrite(grants=(_grant(connection.connection_id),)),
    )
    _ = store.classify_evidence(
        "alpha", "admin", evidence.evidence_id, "local_only"
    )
    rows = db.fetchall("SELECT * FROM model_policy_audit ORDER BY created_at, audit_id")
    serialized = json.dumps(rows)
    assert {row["action"] for row in rows} == {"put_policy", "classify_evidence"}
    assert "payload-must-not-enter-policy-audit" not in serialized
    assert "models_json" not in serialized
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("DELETE FROM model_policy_audit")


def test_store_schema_creation_participates_in_outer_rollback(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "rollback.sqlite"))
    with pytest.raises(RuntimeError):
        _initialize_then_fail(db)
    assert db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='model_policies'"
    ) is None


def _initialize_then_fail(db: Database) -> None:
    with db.transaction():
        _ = ModelPolicyStore(db)
        raise RuntimeError("rollback")
