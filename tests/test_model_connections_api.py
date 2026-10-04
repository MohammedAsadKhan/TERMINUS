"""Authenticated, masked HTTP coverage for named model connections."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from terminus.auth.service import AuthService
from terminus.auth.storage import SqliteSessionStore, SqliteUserStore
from terminus.config import Settings, reset_settings
from terminus.model_gateway.secrets import CredentialCipher
from terminus.orgs.storage import SqliteMembershipStore, SqliteOrganizationStore
from terminus.storage.db import Database

_PASSWORD = "a-test-password-123"
_SECRET = "credential-value-that-must-never-leak"


@pytest.fixture
def api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, Database, Any, dict[str, Any]]]:
    """Build the complete auth and API graph against one isolated durable database."""
    database = Database(str(tmp_path / "model-connections.sqlite3"))
    monkeypatch.setattr(Database, "_instance", database)
    monkeypatch.setenv(
        "TERMINUS_MODEL_CREDENTIALS_KEY",
        CredentialCipher.generate_key().get_secret_value(),
    )
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_PASSWORD", "")
    reset_settings()

    # These globals may already exist when this test runs as part of the full suite.
    # Rebinding them preserves FastAPI dependency identities while isolating state.
    from terminus.server import deps

    monkeypatch.setattr(deps, "_identity_db", database)
    monkeypatch.setattr(deps, "_user_store", SqliteUserStore(database))
    monkeypatch.setattr(deps, "_org_store", SqliteOrganizationStore(database))
    monkeypatch.setattr(deps, "_membership_store", SqliteMembershipStore(database))
    monkeypatch.setattr(
        deps,
        "_auth_service",
        AuthService(
            deps._user_store,
            session_store=SqliteSessionStore(database),
        ),
    )

    from terminus.server.app import create_app

    client = TestClient(create_app())
    identities = _provision_identities(client)
    try:
        yield client, database, deps, identities
    finally:
        client.close()
        database.close()
        reset_settings()


def _register(client: TestClient, label: str) -> dict[str, Any]:
    response = client.post(
        "/auth/register",
        json={
            "email": f"{label}@example.test",
            "password": _PASSWORD,
            "display_name": label,
        },
    )
    assert response.status_code == 201
    return response.json()


def _login(client: TestClient, label: str) -> str:
    response = client.post(
        "/auth/login",
        json={"email": f"{label}@example.test", "password": _PASSWORD},
    )
    assert response.status_code == 200
    token = str(response.json()["session_token"])
    client.cookies.clear()
    return token


def _headers(token: str, org_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "X-Org-ID": org_id}


def _provision_identities(client: TestClient) -> dict[str, Any]:
    users = {
        role: _register(client, role)
        for role in ("admin", "member", "viewer", "orphan", "foreign")
    }
    tokens = {role: _login(client, role) for role in users}

    admin_headers = {"Authorization": f"Bearer {tokens['admin']}"}
    org_response = client.post(
        "/orgs", headers=admin_headers, json={"name": "Model Org"}
    )
    assert org_response.status_code == 201
    org_id = str(org_response.json()["org_id"])
    scoped_admin = _headers(tokens["admin"], org_id)
    for role in ("member", "viewer"):
        response = client.post(
            f"/orgs/{org_id}/members",
            headers=scoped_admin,
            json={"user_id": users[role]["user_id"], "role": role},
        )
        assert response.status_code == 201

    foreign_headers = {"Authorization": f"Bearer {tokens['foreign']}"}
    foreign_response = client.post(
        "/orgs", headers=foreign_headers, json={"name": "Foreign Model Org"}
    )
    assert foreign_response.status_code == 201
    foreign_org_id = str(foreign_response.json()["org_id"])
    return {
        "users": users,
        "tokens": tokens,
        "org_id": org_id,
        "foreign_org_id": foreign_org_id,
        "admin": scoped_admin,
        "member": _headers(tokens["member"], org_id),
        "viewer": _headers(tokens["viewer"], org_id),
        "orphan": _headers(tokens["orphan"], org_id),
        "foreign": _headers(tokens["foreign"], foreign_org_id),
    }


def _create_payload(**changes: Any) -> dict[str, Any]:
    return {
        "name": "Primary OpenAI",
        "provider": "openai",
        "models": ["gpt-4.1"],
        "api_key": _SECRET,
        "enabled": True,
        **changes,
    }


def _create(
    client: TestClient, identities: dict[str, Any], **changes: Any
) -> dict[str, Any]:
    response = client.post(
        "/model-connections",
        headers=identities["admin"],
        json=_create_payload(**changes),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_list_and_get_are_masked_and_encrypted(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, database, _, identities = api
    created = _create(client, identities)
    serialized = json.dumps(created)
    assert _SECRET not in serialized
    assert created["credential_configured"] is True
    assert created["credential_mask"] == "********"
    assert created["verification_status"] == "unverified"
    assert created["version"] == 1
    assert created["base_url"] == "https://api.openai.com/v1"
    assert "api_key" not in created

    listed = client.get("/model-connections", headers=identities["viewer"])
    fetched = client.get(
        f"/model-connections/{created['connection_id']}",
        headers=identities["member"],
    )
    assert listed.status_code == fetched.status_code == 200
    assert listed.json() == [created]
    assert fetched.json() == created
    assert _SECRET not in listed.text + fetched.text

    stored = database.fetchone(
        "SELECT credential_ciphertext FROM model_connections WHERE connection_id = ?",
        (created["connection_id"],),
    )
    assert stored is not None
    assert stored["credential_ciphertext"].startswith("v1.")
    assert _SECRET not in json.dumps(stored)


@pytest.mark.parametrize(
    ("provider", "extra"),
    [
        ("openai", {}),
        ("anthropic", {}),
        ("gemini", {}),
        ("openrouter", {}),
        ("deepseek", {}),
        ("openai_compatible", {"base_url": "https://models.example.test/v1"}),
        ("local", {"base_url": "http://127.0.0.1:11434/v1"}),
    ],
)
def test_supported_provider_metadata_is_registered_without_outbound_io(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
    provider: str,
    extra: dict[str, str],
) -> None:
    client, _, _, identities = api
    response = client.post(
        "/model-connections",
        headers=identities["admin"],
        json={
            "name": f"Provider {provider}",
            "provider": provider,
            "models": ["model-1"],
            **extra,
        },
    )
    assert response.status_code == 201
    assert response.json()["verification_status"] == "unverified"
    assert response.json()["credential_configured"] is False


def test_authentication_live_membership_and_admin_write_role_are_enforced(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, deps, identities = api
    created = _create(client, identities)
    connection_path = f"/model-connections/{created['connection_id']}"

    assert client.get("/model-connections").status_code == 401
    assert (
        client.get("/model-connections", headers=identities["orphan"]).status_code
        == 403
    )
    for role in ("member", "viewer"):
        headers = identities[role]
        assert client.get("/model-connections", headers=headers).status_code == 200
        assert client.get(connection_path, headers=headers).status_code == 200
        assert (
            client.post(
                "/model-connections",
                headers=headers,
                json=_create_payload(name=f"Denied {role}"),
            ).status_code
            == 403
        )
        assert (
            client.patch(
                connection_path,
                headers=headers,
                json={"expected_version": 1, "enabled": False},
            ).status_code
            == 403
        )
        assert (
            client.delete(
                f"{connection_path}?expected_version=1", headers=headers
            ).status_code
            == 403
        )

    from terminus.core.ids import OrgId, UserId

    deps.get_membership_store().delete(
        OrgId(identities["org_id"]),
        UserId(identities["users"]["member"]["user_id"]),
    )
    assert client.get(connection_path, headers=identities["member"]).status_code == 403

    revoked = identities["tokens"]["viewer"]
    assert (
        client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {revoked}"},
        ).status_code
        == 200
    )
    assert client.get(connection_path, headers=identities["viewer"]).status_code == 401


def test_tenant_scope_hides_foreign_connection_ids(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    created = _create(client, identities)
    path = f"/model-connections/{created['connection_id']}"
    assert client.get("/model-connections", headers=identities["foreign"]).json() == []
    assert client.get(path, headers=identities["foreign"]).status_code == 404
    assert (
        client.patch(
            path,
            headers=identities["foreign"],
            json={"expected_version": 1, "enabled": False},
        ).status_code
        == 404
    )
    assert (
        client.delete(
            f"{path}?expected_version=1", headers=identities["foreign"]
        ).status_code
        == 404
    )


def test_update_and_delete_require_current_version(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    created = _create(client, identities)
    path = f"/model-connections/{created['connection_id']}"
    updated = client.patch(
        path,
        headers=identities["admin"],
        json={"expected_version": 1, "models": ["gpt-4.1-mini"], "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["credential_mask"] == "********"
    assert (
        client.patch(
            path,
            headers=identities["admin"],
            json={"expected_version": 1, "enabled": True},
        ).status_code
        == 409
    )
    assert (
        client.delete(
            f"{path}?expected_version=1", headers=identities["admin"]
        ).status_code
        == 409
    )
    assert (
        client.delete(
            f"{path}?expected_version=2", headers=identities["admin"]
        ).status_code
        == 204
    )
    assert client.get(path, headers=identities["admin"]).status_code == 404


def test_duplicate_name_and_missing_ids_return_safe_errors(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    _create(client, identities)
    duplicate = client.post(
        "/model-connections",
        headers=identities["admin"],
        json=_create_payload(api_key="different-secret"),
    )
    assert duplicate.status_code == 409
    assert "different-secret" not in duplicate.text
    assert (
        client.get(
            "/model-connections/missing", headers=identities["admin"]
        ).status_code
        == 404
    )


def test_patch_rejects_invalid_merged_state_and_duplicate_rename(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    primary = _create(client, identities, api_key=None)
    secondary = _create(client, identities, name="Secondary OpenAI", api_key=None)
    primary_path = f"/model-connections/{primary['connection_id']}"

    invalid_provider_change = client.patch(
        primary_path,
        headers=identities["admin"],
        json={"expected_version": 1, "provider": "openai_compatible"},
    )
    assert invalid_provider_change.status_code == 422
    assert invalid_provider_change.json() == {
        "detail": "Invalid model connection request"
    }

    duplicate_rename = client.patch(
        primary_path,
        headers=identities["admin"],
        json={"expected_version": 1, "name": secondary["name"]},
    )
    assert duplicate_rename.status_code == 409


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "Bad", "provider": "unknown", "models": ["m"], "api_key": _SECRET},
        {
            "name": "Bad",
            "provider": "openai",
            "models": ["m"],
            "api_key": {"nested": _SECRET},
        },
        {"name": "Bad", "provider": "openai", "models": ["m"], "api_key": [_SECRET]},
        {"name": "Bad", "provider": "openai", "models": [_SECRET, {"value": _SECRET}]},
        {
            "name": "Bad",
            "provider": "openai",
            "models": ["m"],
            "nested": {"api_key": _SECRET},
        },
    ],
)
def test_validation_never_echoes_nested_or_invalid_typed_credentials(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
    payload: dict[str, Any],
) -> None:
    client, _, _, identities = api
    response = client.post(
        "/model-connections", headers=identities["admin"], json=payload
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid model connection request"}
    assert _SECRET not in response.text


def test_router_redacts_malformed_json_and_query_validation_values(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    malformed = client.post(
        "/model-connections",
        headers={**identities["admin"], "Content-Type": "application/json"},
        content='{"name":"' + _SECRET,
    )
    assert malformed.status_code == 422
    assert malformed.json() == {"detail": "Invalid model connection request"}
    assert _SECRET not in malformed.text

    created = _create(client, identities)
    invalid_query = client.delete(
        f"/model-connections/{created['connection_id']}?expected_version={_SECRET}",
        headers=identities["admin"],
    )
    assert invalid_query.status_code == 422
    assert invalid_query.json() == {"detail": "Invalid model connection request"}
    assert _SECRET not in invalid_query.text


def test_missing_key_allows_metadata_but_rejects_credentials_safely(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, _, _, identities = api
    from terminus.config import get_settings

    existing = _create(client, identities)
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        _env_file=None, model_credentials_key=""
    )
    metadata = client.post(
        "/model-connections",
        headers=identities["admin"],
        json={
            "name": "Local metadata",
            "provider": "local",
            "base_url": "http://localhost:11434",
            "models": ["qwen"],
        },
    )
    assert metadata.status_code == 201
    assert metadata.json()["credential_mask"] is None
    denied = client.post(
        "/model-connections",
        headers=identities["admin"],
        json=_create_payload(name="Secret without key"),
    )
    assert denied.status_code == 503
    assert denied.json() == {"detail": "Model connection storage is unavailable"}
    assert _SECRET not in denied.text
    listed = client.get("/model-connections", headers=identities["viewer"])
    assert listed.status_code == 200
    by_id = {item["connection_id"]: item for item in listed.json()}
    assert by_id[existing["connection_id"]]["credential_mask"] == "********"


def test_invalid_master_key_and_damaged_ciphertext_are_generic_503s(
    api: tuple[TestClient, Database, Any, dict[str, Any]],
) -> None:
    client, database, _, identities = api
    from terminus.config import get_settings

    configured = _create(client, identities)
    invalid_key = "invalid-master-key-that-must-not-leak"
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        _env_file=None, model_credentials_key=invalid_key
    )
    unavailable = client.get("/model-connections", headers=identities["admin"])
    assert unavailable.status_code == 503
    assert unavailable.json() == {"detail": "Model connection storage is unavailable"}
    assert invalid_key not in unavailable.text

    client.app.dependency_overrides.pop(get_settings)
    database.execute(
        "UPDATE model_connections SET credential_ciphertext = ? WHERE connection_id = ?",
        ("v1.damaged-ciphertext", configured["connection_id"]),
    )
    damaged = client.get(
        f"/model-connections/{configured['connection_id']}",
        headers=identities["admin"],
    )
    assert damaged.status_code == 503
    assert damaged.json() == {"detail": "Model connection storage is unavailable"}
    assert "damaged-ciphertext" not in damaged.text
