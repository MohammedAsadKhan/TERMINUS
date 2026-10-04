"""Bootstrap never restores access or creates fixed credentials in hosted mode."""

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from terminus.auth.service import AuthError, AuthService
from terminus.auth.storage import SqliteSessionStore, SqliteUserStore
from terminus.config import Settings, get_settings, reset_settings
from terminus.core.ids import OrgId
from terminus.licensing.models import LicenseTier
from terminus.licensing.service import LicenseService
from terminus.orgs.storage import SqliteMembershipStore, SqliteOrganizationStore
from terminus.storage.db import Database


@pytest.fixture
def identity(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "bootstrap.db"))
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: db)
    from terminus.server import deps

    users = SqliteUserStore(db)
    members = SqliteMembershipStore(db)
    auth = AuthService(users, session_store=SqliteSessionStore(db))
    for key, value in {
        "_identity_db": db,
        "_user_store": users,
        "_org_store": SqliteOrganizationStore(db),
        "_membership_store": members,
        "_auth_service": auth,
    }.items():
        monkeypatch.setattr(deps, key, value)
    return SimpleNamespace(db=db, deps=deps, users=users, members=members, auth=auth)


def settings(**kwargs):
    return Settings(
        _env_file=None,
        license_secret="test-stable-secret",
        token_secret="test-token-secret",
        **kwargs,
    )


def test_hosted_bootstrap_is_explicit_and_does_not_restore_password_or_membership(
    identity, monkeypatch
):
    env = identity
    monkeypatch.setattr(
        env.deps, "get_settings", lambda: settings(deployment_mode="hosted")
    )
    before = env.db.fetchone("SELECT COUNT(*) AS n FROM users")["n"]
    env.deps.bootstrap_default_admin()
    assert env.db.fetchone("SELECT COUNT(*) AS n FROM users")["n"] == before
    configured = settings(
        deployment_mode="hosted",
        bootstrap_admin_email="owner@example.test",
        bootstrap_admin_password="first-password-123",
    )
    monkeypatch.setattr(env.deps, "get_settings", lambda: configured)
    env.deps.bootstrap_default_admin()
    user = env.users.get_by_email("owner@example.test")
    membership = env.members.orgs_for_user(user.user_id)[0]
    env.auth.login(user.email, "first-password-123")
    env.members.delete(membership.org_id, user.user_id)
    monkeypatch.setattr(
        env.deps,
        "get_settings",
        lambda: settings(
            deployment_mode="hosted",
            bootstrap_admin_email=user.email,
            bootstrap_admin_password="replacement-password-123",
        ),
    )
    env.deps.bootstrap_default_admin()
    assert env.members.orgs_for_user(user.user_id) == []
    env.auth.login(user.email, "first-password-123")
    with pytest.raises(AuthError):
        env.auth.login(user.email, "replacement-password-123")


def test_bootstrap_failure_rolls_back_user_and_organization(identity, monkeypatch):
    env = identity
    monkeypatch.setattr(
        env.deps,
        "get_settings",
        lambda: settings(
            bootstrap_admin_email="rollback@example.test",
            bootstrap_admin_password="first-password-123",
        ),
    )
    before = env.db.fetchone("SELECT COUNT(*) AS n FROM organizations")["n"]

    def fail(*args, **kwargs):
        raise RuntimeError("Membership write unavailable")

    monkeypatch.setattr(env.members, "create", fail)
    with pytest.raises(RuntimeError, match="Membership write unavailable"):
        env.deps.bootstrap_default_admin()
    assert env.users.get_by_email("rollback@example.test") is None
    assert env.db.fetchone("SELECT COUNT(*) AS n FROM organizations")["n"] == before


def test_hosted_configuration_requires_stable_license_secret_and_secure_cookie():
    with pytest.raises(ValidationError, match="stable TERMINUS_LICENSE_SECRET"):
        Settings(_env_file=None, deployment_mode="hosted", license_secret="")
    with pytest.raises(ValidationError, match="configured together"):
        settings(bootstrap_admin_email="owner@example.test")
    hosted = settings(
        deployment_mode="hosted",
        bootstrap_admin_email="owner@example.test",
        bootstrap_admin_password="first-password-123",
    )
    assert hosted.cookie_secure
    assert "bootstrap_admin_password" not in hosted.model_dump()
    assert "first-password-123" not in repr(hosted)


def test_local_license_signer_survives_fresh_settings_and_database(
    tmp_path, monkeypatch
):
    db_path = str(tmp_path / "local-secret.db")
    db = Database(db_path)
    monkeypatch.setattr(Database, "get_instance", lambda *args, **kwargs: db)
    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("TERMINUS_LICENSE_SECRET", "")
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setenv("TERMINUS_BOOTSTRAP_ADMIN_PASSWORD", "")
    reset_settings()
    try:
        first = get_settings()
        token = LicenseService(secret=first.license_secret).generate(
            org_id=OrgId("org-test"), tier=LicenseTier.TRIAL, days=30
        )
        db = Database(db_path)
        reset_settings()
        reopened = get_settings()
        assert reopened.license_secret == first.license_secret
        assert (
            LicenseService(secret=reopened.license_secret).validate(token).org_id
            == "org-test"
        )
    finally:
        reset_settings()


def test_hosted_mode_rejects_imported_demo_login_and_old_session(identity, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from terminus.server import routers

    env = identity
    user = env.users.get_by_email("admin@terminus.local")
    if user is None:
        user = env.auth.register("admin@terminus.local", "Password123!", "Local Demo")
    old_token = env.auth.login(user.email, "Password123!")
    hosted = settings(deployment_mode="hosted")
    monkeypatch.setattr(env.deps, "get_settings", lambda: hosted)
    monkeypatch.setattr(routers, "get_settings", lambda: hosted)
    app = FastAPI()
    app.include_router(routers.auth_router)
    app.include_router(routers.org_router)
    client = TestClient(app)
    assert (
        client.post(
            "/auth/login", json={"email": user.email, "password": "Password123!"}
        ).status_code
        == 401
    )
    assert (
        client.get("/orgs", headers={"X-Session-Token": old_token}).status_code == 401
    )
