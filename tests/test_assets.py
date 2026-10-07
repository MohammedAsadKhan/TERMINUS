"""Tests for the organization-scoped asset inventory API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

import pytest
from fastapi import Header
from fastapi.testclient import TestClient

from terminus.auth.models import User
from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import OrganizationRole
from terminus.server.app import create_app
from terminus.server.assets_api import get_asset_repository
from terminus.server.deps import get_current_org, get_current_user, get_membership_store
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database


class _Memberships:
    def role_of(self, org_id: str, user_id: str) -> OrganizationRole | None:
        if org_id == "org-a" and user_id == "user-admin":
            return OrganizationRole.ADMIN
        if org_id == "org-a" and user_id == "user-member":
            return OrganizationRole.MEMBER
        if org_id == "org-b" and user_id == "user-admin":
            return OrganizationRole.ADMIN
        return None


@pytest.fixture
def client(tmp_path: pytest.TempPathFactory) -> TestClient:
    db_path = str(tmp_path / "assets-test.db")
    app = create_app()

    def current_user(
        user_id: Annotated[str, Header(alias="X-Test-User")] = "user-admin",
    ) -> User:
        return User(
            user_id=UserId(user_id),
            email=f"{user_id}@example.test",
            password_hash="not-used",
            display_name=user_id,
            created_at=datetime.now(UTC),
        )

    def current_org(
        org_id: Annotated[str, Header(alias="X-Org-ID")] = "org-a",
    ) -> OrgId:
        return OrgId(org_id)

    app.dependency_overrides[get_current_user] = current_user
    app.dependency_overrides[get_current_org] = current_org
    def memberships() -> _Memberships:
        return _Memberships()

    app.dependency_overrides[get_membership_store] = memberships
    app.dependency_overrides[get_asset_repository] = lambda: SqliteAssetRepository(Database(db_path))
    return TestClient(app)


def test_asset_create_filter_and_persist_with_coverage(client: TestClient, tmp_path: pytest.TempPathFactory) -> None:
    response = client.post(
        "/assets",
        json={
            "kind": "repository",
            "name": "Terminus source",
            "locator": "https://github.com/example/terminus",
            "notes": "Production codebase",
        },
    )
    assert response.status_code == 201
    asset = response.json()
    assert asset["org_id"] == "org-a"
    assert asset["kind"] == "repository"
    assert asset["coverage"] == "never_scanned"
    assert asset["source"] == "manual"
    assert asset["asset_id"]

    assert client.get("/assets?kind=repository").json() == [asset]
    assert client.get("/assets?kind=device").json() == []

    # A fresh database handle sees the stored row, proving data is durable in SQLite.
    persisted = SqliteAssetRepository(Database(str(tmp_path / "assets-test.db")))
    assert persisted.list_for_org("org-a")[0]["asset_id"] == asset["asset_id"]


def test_inventory_is_organization_scoped_and_delete_hides_foreign_id(client: TestClient) -> None:
    asset = client.post("/assets", json={"kind": "device", "name": "Workstation 4"}).json()

    assert client.get("/assets", headers={"X-Org-ID": "org-b"}).json() == []
    assert client.delete(f"/assets/{asset['asset_id']}", headers={"X-Org-ID": "org-b"}).status_code == 404
    assert client.get("/assets").json()[0]["asset_id"] == asset["asset_id"]
    assert client.delete(f"/assets/{asset['asset_id']}").status_code == 204


def test_only_admins_can_write_assets(client: TestClient) -> None:
    headers = {"X-Test-User": "user-member"}
    assert client.get("/assets", headers=headers).status_code == 200
    assert client.post("/assets", headers=headers, json={"kind": "cloud", "name": "AWS"}).status_code == 403
    assert client.delete("/assets/missing", headers=headers).status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "unknown", "name": "bad kind"},
        {"kind": "cloud", "name": ""},
        {"kind": "cloud", "name": "A" * 201},
        {"kind": "cloud", "name": "prod", "notes": "api_key=topsecret"},
        {"kind": "cloud", "name": "prod", "extra": "ignored fields are not accepted"},
    ],
)
def test_asset_input_validation(client: TestClient, payload: dict[str, str]) -> None:
    assert client.post("/assets", json=payload).status_code == 422

