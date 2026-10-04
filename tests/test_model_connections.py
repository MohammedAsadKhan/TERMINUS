"""Tenant, validation, concurrency, and credential tests for model connections."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import SecretStr, ValidationError

from terminus.model_gateway import (
    CLOUD_PROVIDER_URLS,
    ConnectionConflictError,
    ConnectionDeniedError,
    ConnectionNotFoundError,
    ConnectionUnavailableError,
    ConnectionValidationError,
    CredentialCipher,
    ModelConnectionCreate,
    ModelConnectionStore,
    ModelConnectionUpdate,
)
from terminus.storage.db import Database


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
def registry(tmp_path: Path):
    db = Database(str(tmp_path / "connections.sqlite"))
    _identity(db, "alpha", "admin", "admin")
    _identity(db, "alpha", "analyst", "member")
    _identity(db, "alpha", "viewer", "viewer")
    _identity(db, "bravo", "other-admin", "admin")
    cipher = CredentialCipher.from_key(CredentialCipher.generate_key().get_secret_value())
    return db, cipher, ModelConnectionStore(db, cipher)


def _create(
    store: ModelConnectionStore,
    *,
    org_id: str = "alpha",
    actor: str = "admin",
    name: str = "Primary",
    provider: str = "openai",
    api_key: SecretStr | None = None,
):
    return store.create(
        org_id,
        actor,
        ModelConnectionCreate(
            name=name,
            provider=provider,
            models=["model-1"],
            api_key=api_key,
        ),
    )


def test_all_provider_metadata_is_strict_and_unverified(registry) -> None:
    _, _, store = registry
    providers = {
        **CLOUD_PROVIDER_URLS,
        "openai_compatible": "https://models.example.test/v1",
        "local": "http://127.0.0.1:11434/v1",
    }
    for index, (provider, endpoint) in enumerate(providers.items()):
        request = ModelConnectionCreate(
            name=f"Connection {index}",
            provider=provider,
            base_url=None if provider in CLOUD_PROVIDER_URLS else endpoint,
            models=[f"vendor/model-{index}"],
        )
        result = store.create("alpha", "admin", request)
        assert result.base_url == endpoint
        assert result.verification_status == "unverified"
        assert result.enabled is False
        assert result.credential_configured is False
        assert result.credential_mask is None

    with pytest.raises(ValidationError):
        ModelConnectionCreate(
            name="Extra",
            provider="openai",
            models=["gpt"],
            unexpected=True,
        )
    with pytest.raises(ValidationError):
        ModelConnectionCreate(name="Loose", provider="openai", models=["same", "same"])
    with pytest.raises(ValidationError):
        ModelConnectionCreate(name="Loose", provider="openai", models=["has space"])


@pytest.mark.parametrize(
    ("provider", "url"),
    [
        ("openai", "https://evil.example/v1"),
        ("openai_compatible", "http://models.example.test/v1"),
        ("openai_compatible", "https://user:pass@models.example.test/v1"),
        ("openai_compatible", "https://models.example.test/v1?api_key=secret"),
        ("local", "http://models.example.test/v1"),
        ("local", "http://8.8.8.8/v1"),
    ],
)
def test_endpoint_policy_rejects_credential_and_network_bypasses(
    provider: str, url: str
) -> None:
    with pytest.raises(ValidationError):
        ModelConnectionCreate(
            name="Unsafe", provider=provider, base_url=url, models=["model"]
        )


def test_https_local_company_endpoint_and_secret_markers() -> None:
    assert (
        ModelConnectionCreate(
            name="Company Models",
            provider="local",
            base_url="https://models.corp.example/v1",
            models=["model"],
        ).base_url
        == "https://models.corp.example/v1"
    )
    for name in ("sk-proj-abcdefghijk", "API key abcdefghijk"):
        with pytest.raises(ValidationError):
            ModelConnectionCreate(name=name, provider="openai", models=["model"])


def test_membership_is_live_and_reads_allow_every_current_role(registry) -> None:
    db, _, store = registry
    connection = _create(store)
    assert store.get("alpha", "analyst", connection.connection_id) == connection
    assert store.list_for_org("alpha", "viewer") == [connection]
    with pytest.raises(ConnectionDeniedError):
        _create(store, actor="analyst", name="Denied")

    db.execute(
        "UPDATE memberships SET role = 'member' WHERE org_id = 'alpha' AND user_id = 'admin'"
    )
    with pytest.raises(ConnectionDeniedError):
        store.update(
            "alpha",
            "admin",
            connection.connection_id,
            ModelConnectionUpdate(expected_version=1, enabled=True),
        )
    db.execute(
        "DELETE FROM memberships WHERE org_id = 'alpha' AND user_id = 'viewer'"
    )
    with pytest.raises(ConnectionDeniedError):
        store.get("alpha", "viewer", connection.connection_id)


def test_foreign_and_missing_identifiers_are_indistinguishable(registry) -> None:
    _, _, store = registry
    foreign = _create(store, org_id="bravo", actor="other-admin", name="Foreign")
    errors = []
    for connection_id in (foreign.connection_id, "missing"):
        with pytest.raises(ConnectionNotFoundError) as caught:
            store.get("alpha", "admin", connection_id)
        errors.append(str(caught.value))
    assert errors == ["Model connection not found"] * 2


def test_key_is_encrypted_masked_and_never_serialized_or_audited(registry) -> None:
    db, _, store = registry
    plaintext = "sk-test-super-secret-value"
    request = ModelConnectionCreate(
        name="Credentialed",
        provider="anthropic",
        models=["claude-test"],
        api_key=SecretStr(plaintext),
    )
    assert plaintext not in repr(request)
    assert "api_key" not in request.model_dump()
    assert plaintext not in request.model_dump_json()

    view = store.create("alpha", "admin", request)
    assert view.credential_configured is True
    assert view.credential_mask == "********"
    raw = db.fetchone(
        "SELECT * FROM model_connections WHERE connection_id = ?",
        (view.connection_id,),
    )
    assert raw is not None
    assert raw["credential_ciphertext"] != plaintext
    assert plaintext not in json.dumps(raw)
    audits = db.fetchall("SELECT * FROM model_connection_audit")
    assert plaintext not in json.dumps(audits)
    assert "api_key" not in json.dumps(audits)
    assert "credential" in json.loads(audits[0]["changed_fields_json"])


def test_restart_retain_rotate_clear_and_provider_change_guard(registry) -> None:
    db, cipher, store = registry
    created = _create(store, api_key=SecretStr("first-secret"))
    restarted = ModelConnectionStore(Database(db.db_path), cipher)
    retained = restarted.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(expected_version=1, name="Renamed"),
    )
    assert retained.credential_configured is True
    with pytest.raises(ConnectionConflictError):
        restarted.update(
            "alpha",
            "admin",
            created.connection_id,
            ModelConnectionUpdate(expected_version=2, provider="anthropic"),
        )
    rotated = restarted.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(
            expected_version=2,
            provider="anthropic",
            api_key=SecretStr("second-secret"),
        ),
    )
    assert rotated.base_url == CLOUD_PROVIDER_URLS["anthropic"]
    cleared = restarted.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(expected_version=3, api_key=None),
    )
    assert cleared.credential_configured is False
    assert cleared.credential_mask is None


def test_invalid_merged_patch_and_duplicate_rename_are_domain_errors(registry) -> None:
    _, _, store = registry
    first = _create(store, name="First")
    second = _create(store, name="Second")
    with pytest.raises(ConnectionValidationError):
        store.update(
            "alpha",
            "admin",
            first.connection_id,
            ModelConnectionUpdate(expected_version=1, provider="openai_compatible"),
        )
    with pytest.raises(ConnectionConflictError):
        store.update(
            "alpha",
            "admin",
            second.connection_id,
            ModelConnectionUpdate(expected_version=1, name="FIRST"),
        )


def test_endpoint_change_requires_explicit_credential_decision(registry) -> None:
    _, _, store = registry
    created = store.create(
        "alpha",
        "admin",
        ModelConnectionCreate(
            name="Compatible",
            provider="openai_compatible",
            base_url="https://one.example/v1",
            models=["model"],
            api_key=SecretStr("existing-secret"),
        ),
    )
    with pytest.raises(ConnectionConflictError):
        store.update(
            "alpha",
            "admin",
            created.connection_id,
            ModelConnectionUpdate(
                expected_version=1, base_url="https://two.example/v1"
            ),
        )
    changed = store.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(
            expected_version=1,
            base_url="https://two.example/v1",
            api_key=SecretStr("replacement-secret"),
        ),
    )
    assert changed.base_url == "https://two.example/v1"


def test_absent_cipher_allows_metadata_retain_and_clear_but_not_new_secret(registry) -> None:
    db, _, encrypted_store = registry
    created = _create(encrypted_store, api_key=SecretStr("existing-secret"))
    store = ModelConnectionStore(db, None)
    retained = store.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(expected_version=1, enabled=True),
    )
    assert retained.credential_configured is True
    cleared = store.update(
        "alpha",
        "admin",
        created.connection_id,
        ModelConnectionUpdate(expected_version=2, api_key=None),
    )
    assert cleared.credential_configured is False
    with pytest.raises(ConnectionUnavailableError):
        _create(store, name="Cannot Encrypt", api_key=SecretStr("new-secret"))
    with pytest.raises(ConnectionUnavailableError):
        store.update(
            "alpha",
            "admin",
            created.connection_id,
            ModelConnectionUpdate(expected_version=3, api_key=SecretStr("new-secret")),
        )


def test_tampering_and_wrong_key_fail_closed_without_secret_details(registry) -> None:
    db, _, store = registry
    created = _create(store, api_key=SecretStr("never-show-this"))
    wrong = CredentialCipher.from_key(CredentialCipher.generate_key().get_secret_value())
    wrong_store = ModelConnectionStore(db, wrong)
    with pytest.raises(ConnectionUnavailableError) as caught:
        wrong_store.update(
            "alpha",
            "admin",
            created.connection_id,
            ModelConnectionUpdate(expected_version=1, name="No Mutation"),
        )
    assert "never-show-this" not in str(caught.value)

    db.execute(
        "UPDATE model_connections SET credential_ciphertext = 'v1.invalid' WHERE connection_id = ?",
        (created.connection_id,),
    )
    with pytest.raises(ConnectionUnavailableError) as caught:
        store.delete("alpha", "admin", created.connection_id, 1)
    assert "invalid" not in str(caught.value)
    assert db.fetchone(
        "SELECT name FROM model_connections WHERE connection_id = ?",
        (created.connection_id,),
    ) == {"name": "Primary"}


def test_concurrent_cas_and_case_insensitive_uniqueness(registry) -> None:
    _, _, store = registry
    created = _create(store)
    barrier = Barrier(2)

    def mutate(name: str):
        barrier.wait()
        try:
            return store.update(
                "alpha",
                "admin",
                created.connection_id,
                ModelConnectionUpdate(expected_version=1, name=name),
            )
        except ConnectionConflictError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(mutate, ["Winner One", "Winner Two"]))
    assert sum(result is not None for result in results) == 1
    assert store.get("alpha", "admin", created.connection_id).version == 2

    with pytest.raises(ConnectionConflictError):
        _create(store, name=store.get("alpha", "admin", created.connection_id).name.swapcase())


def test_quota_is_enforced_inside_writer_transaction(registry) -> None:
    _, _, store = registry
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                lambda index: _try_create(store, index),
                range(60),
            )
        )
    assert outcomes.count(True) == 50
    assert outcomes.count(False) == 10
    assert len(store.list_for_org("alpha", "admin")) == 50


def _try_create(store: ModelConnectionStore, index: int) -> bool:
    try:
        _create(store, name=f"Quota {index}")
    except ConnectionConflictError:
        return False
    return True


def test_delete_is_cas_and_audit_is_immutable_and_redacted(registry) -> None:
    db, _, store = registry
    created = _create(store, api_key=SecretStr("audit-secret"))
    with pytest.raises(ConnectionConflictError):
        store.delete("alpha", "admin", created.connection_id, 2)
    store.delete("alpha", "admin", created.connection_id, 1)
    with pytest.raises(ConnectionNotFoundError):
        store.get("alpha", "admin", created.connection_id)
    rows = db.fetchall(
        "SELECT action, changed_fields_json FROM model_connection_audit ORDER BY created_at"
    )
    assert [row["action"] for row in rows] == ["create", "delete"]
    assert "audit-secret" not in json.dumps(rows)
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("DELETE FROM model_connection_audit")


def test_store_schema_creation_participates_in_outer_rollback(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "rollback.sqlite"))
    with pytest.raises(RuntimeError):
        _initialize_then_fail(db)
    assert db.fetchone(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='model_connections'"
    ) is None


def _initialize_then_fail(db: Database) -> None:
    with db.transaction():
        ModelConnectionStore(db, None)
        raise RuntimeError("rollback")


def test_store_boundary_revalidates_constructed_and_mutated_requests(registry) -> None:
    _, _, store = registry
    hostile = ModelConnectionCreate.model_construct(
        name="Unsafe",
        provider="openai_compatible",
        base_url="http://user:pass@evil.example/v1?key=value",
        models=["model"],
        api_key=None,
        enabled=False,
    )
    with pytest.raises(ConnectionValidationError):
        store.create("alpha", "admin", hostile)
    assert store.list_for_org("alpha", "admin") == []

    created = _create(store)
    bypass = ModelConnectionUpdate.model_construct(
        expected_version=True,
        models=["bad model id"],
    )
    with pytest.raises(ConnectionValidationError):
        store.update("alpha", "admin", created.connection_id, bypass)
    unchanged = store.get("alpha", "admin", created.connection_id)
    assert unchanged.version == 1
    assert unchanged.models == ["model-1"]
