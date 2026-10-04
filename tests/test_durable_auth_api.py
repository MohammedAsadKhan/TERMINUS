"""Integration coverage for SQLite-backed authentication and tenant membership."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from terminus.auth.service import AuthService
from terminus.auth.storage import SqliteSessionStore, SqliteUserStore
from terminus.config import reset_settings
from terminus.orgs.storage import SqliteMembershipStore, SqliteOrganizationStore
from terminus.storage.db import Database


def _client_for_database(
    db_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[TestClient, Any, Database]:
    """Build fresh server services around an isolated SQLite file."""
    database = Database(str(db_path))
    monkeypatch.setattr(
        Database,
        "get_instance",
        classmethod(lambda cls, db_path="terminus.db": database),
    )
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_PASSWORD", "")
    reset_settings()

    # Keep FastAPI dependency function identities stable across the suite. The
    # getters read these module globals, so swapping their backing stores gives
    # each simulated process a fresh service graph without reloading routers.
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

    return TestClient(create_app()), deps, database


@pytest.fixture
def isolated_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[tuple[TestClient, Any, Database, Path]]:
    db_path = tmp_path / "durable-auth.sqlite3"
    client, deps, database = _client_for_database(db_path, monkeypatch)
    yield client, deps, database, db_path
    client.close()


def _register(client: TestClient, email: str, display_name: str) -> dict[str, Any]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "a-test-password-123",
            "display_name": display_name,
        },
    )
    assert response.status_code == 201
    return response.json()


def _login(client: TestClient, email: str) -> tuple[str, dict[str, str]]:
    response = client.post(
        "/auth/login",
        json={"email": email, "password": "a-test-password-123"},
    )
    assert response.status_code == 200
    payload = response.json()
    token = payload["session_token"]
    return token, {"Authorization": f"Bearer {token}"}


def test_register_login_orgs_and_logout_survive_service_reopen(
    isolated_client: tuple[TestClient, Any, Database, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, _, db_path = isolated_client
    public_user = _register(client, "durable@example.test", "Durable User")
    assert "password_hash" not in public_user
    assert "session_digest" not in public_user

    token, headers = _login(client, "durable@example.test")
    login_user = client.post(
        "/auth/login",
        json={"email": "durable@example.test", "password": "a-test-password-123"},
    ).json()["user"]
    assert "password_hash" not in login_user
    assert "session_digest" not in login_user

    created_org = client.post("/orgs", headers=headers, json={"name": "Durable Org"})
    assert created_org.status_code == 201
    org_id = created_org.json()["org_id"]
    assert [org["org_id"] for org in client.get("/orgs", headers=headers).json()] == [org_id]

    # A new database and service graph use the same file, as on process restart.
    reopened, _, _ = _client_for_database(db_path, monkeypatch)
    new_token, new_headers = _login(reopened, "durable@example.test")
    assert new_token != token
    assert [org["org_id"] for org in reopened.get("/orgs", headers=new_headers).json()] == [org_id]
    assert reopened.get("/workflows/runs", headers=new_headers).status_code == 200
    assert reopened.get("/workflows/runs", headers=headers).status_code == 200

    logout = reopened.post("/auth/logout", headers=new_headers)
    assert logout.status_code == 200
    assert reopened.get("/workflows/runs", headers=new_headers).status_code == 401

    after_logout, _, _ = _client_for_database(db_path, monkeypatch)
    assert after_logout.get(
        "/workflows/runs", headers={"Authorization": f"Bearer {new_token}"}
    ).status_code == 401


def test_nonmembers_and_cross_organization_headers_are_denied(
    isolated_client: tuple[TestClient, Any, Database, Path],
) -> None:
    client, _, _, _ = isolated_client
    _register(client, "owner-a@example.test", "Owner A")
    _, owner_a_headers = _login(client, "owner-a@example.test")
    org_a = client.post("/orgs", headers=owner_a_headers, json={"name": "Org A"}).json()["org_id"]

    _register(client, "owner-b@example.test", "Owner B")
    _, owner_b_headers = _login(client, "owner-b@example.test")
    org_b = client.post("/orgs", headers=owner_b_headers, json={"name": "Org B"}).json()["org_id"]

    assert client.get(
        "/workflows/runs", headers={**owner_a_headers, "X-Org-ID": org_b}
    ).status_code == 403

    _register(client, "orphan@example.test", "Orphan")
    _, orphan_headers = _login(client, "orphan@example.test")
    assert client.get("/workflows/runs", headers=orphan_headers).status_code == 403
    assert client.get(
        "/workflows/runs", headers={**orphan_headers, "X-Org-ID": org_a}
    ).status_code == 403
    assert client.get("/orgs", headers=owner_b_headers).json()[0]["org_id"] == org_b


def test_membership_role_change_and_removal_persist_for_existing_session(
    isolated_client: tuple[TestClient, Any, Database, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, deps, _, db_path = isolated_client
    owner = _register(client, "owner@example.test", "Owner")
    _, owner_headers = _login(client, "owner@example.test")
    org_id = client.post("/orgs", headers=owner_headers, json={"name": "Membership Org"}).json()["org_id"]

    member = _register(client, "member@example.test", "Member")
    member_token, member_headers = _login(client, "member@example.test")
    add = client.post(
        f"/orgs/{org_id}/members",
        headers=owner_headers,
        json={"user_id": member["user_id"], "role": "member"},
    )
    assert add.status_code == 201
    assert client.get("/workflows/runs", headers=member_headers).status_code == 200

    org_service = deps.get_org_service(
        deps.get_org_store(),
        deps.get_membership_store(),
        deps.get_license_service(deps.get_settings()),
    )
    from terminus.core.ids import OrgId, UserId
    from terminus.orgs.models import OrganizationRole

    org_service.change_role(
        OrgId(org_id),
        actor_id=UserId(owner["user_id"]),
        user_id=UserId(member["user_id"]),
        new_role=OrganizationRole.VIEWER,
    )

    reopened, reopened_deps, _ = _client_for_database(db_path, monkeypatch)
    membership = reopened_deps.get_membership_store().get(
        OrgId(org_id), UserId(member["user_id"])
    )
    assert membership.role == OrganizationRole.VIEWER
    denied_admin_action = reopened.post(
        f"/orgs/{org_id}/members",
        headers=member_headers,
        json={"user_id": owner["user_id"], "role": "member"},
    )
    assert denied_admin_action.status_code == 403
    assert reopened.get("/workflows/runs", headers=member_headers).status_code == 200

    reopened_org_service = reopened_deps.get_org_service(
        reopened_deps.get_org_store(),
        reopened_deps.get_membership_store(),
        reopened_deps.get_license_service(reopened_deps.get_settings()),
    )
    reopened_org_service.remove_member(
        OrgId(org_id),
        actor_id=UserId(owner["user_id"]),
        user_id=UserId(member["user_id"]),
    )
    assert reopened.get("/workflows/runs", headers=member_headers).status_code == 403

    after_removal, _, _ = _client_for_database(db_path, monkeypatch)
    assert after_removal.get(
        "/workflows/runs", headers={"Authorization": f"Bearer {member_token}"}
    ).status_code == 403
