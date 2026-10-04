from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Barrier

import pytest

from terminus.auth.password import hash_password, verify_password
from terminus.auth.service import AuthError, AuthService, DuplicateEmailError
from terminus.auth.storage import SqliteSessionStore, SqliteUserStore
from terminus.storage.db import Database


def auth_for(db: Database) -> AuthService:
    return AuthService(SqliteUserStore(db), SqliteSessionStore(db))


def test_user_and_session_survive_restart_with_only_hashes_stored(tmp_path):
    path = str(tmp_path / "auth.db")
    db = Database(path)
    auth = auth_for(db)
    user = auth.register("  ADMIN@Example.com  ", "a-secret-password", "Admin")
    issued_at = datetime.now(UTC)
    token = auth.login(" ADMIN@example.COM ", "a-secret-password")

    row = db.fetchone("SELECT * FROM users")
    session = db.fetchone("SELECT * FROM sessions")
    assert row["email"] == "admin@example.com"
    assert row["password_hash"] != "a-secret-password"
    assert verify_password("a-secret-password", row["password_hash"])
    assert session["token_hash"] == sha256(token.encode()).hexdigest()
    assert token not in str(session)
    expires = datetime.fromisoformat(session["expires_at"])
    assert expires.tzinfo == UTC
    assert issued_at + timedelta(hours=12) <= expires
    assert expires < datetime.now(UTC) + timedelta(hours=12)

    restarted = auth_for(Database(path))
    assert restarted.verify(token) == user
    new_token = restarted.login("admin@example.com", "a-secret-password")
    assert new_token != token
    assert auth.verify(new_token) == user


def test_revocation_is_shared_and_survives_restart(tmp_path):
    path = str(tmp_path / "auth.db")
    first = auth_for(Database(path))
    first.register("user@example.com", "secret", "User")
    token = first.login("user@example.com", "secret")
    second = auth_for(Database(path))
    second.logout(token)
    second.logout(token)
    second.logout("unknown-token")

    for auth in (first, second, auth_for(Database(path))):
        with pytest.raises(AuthError, match="Invalid or expired"):
            auth.verify(token)


def test_expiry_survives_restart(tmp_path):
    path = str(tmp_path / "auth.db")
    db = Database(path)
    auth = auth_for(db)
    auth.register("user@example.com", "secret", "User")
    token = auth.login("user@example.com", "secret")
    digest = sha256(token.encode()).hexdigest()
    db.execute(
        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
        ((datetime.now(UTC) - timedelta(seconds=1)).isoformat(), digest),
    )
    with pytest.raises(AuthError, match="Invalid or expired"):
        auth_for(Database(path)).verify(token)
    assert db.fetchone("SELECT revoked_at FROM sessions")["revoked_at"] is not None
    with pytest.raises(AuthError):
        auth_for(Database(path)).verify(token)


def test_verify_and_login_read_current_user_and_deletion_invalidates_session(tmp_path):
    db = Database(str(tmp_path / "auth.db"))
    auth = auth_for(db)
    user = auth.register("user@example.com", "secret", "User")
    token = auth.login("user@example.com", "secret")
    db.execute(
        "UPDATE users SET display_name = ?, password_hash = ? WHERE user_id = ?",
        ("Updated", hash_password("replacement"), str(user.user_id)),
    )
    assert auth.verify(token).display_name == "Updated"
    with pytest.raises(AuthError):
        auth.login("user@example.com", "secret")
    assert (
        auth.verify(auth.login("user@example.com", "replacement")).user_id
        == user.user_id
    )
    db.execute("DELETE FROM users WHERE user_id = ?", (str(user.user_id),))
    assert db.fetchone("SELECT * FROM sessions") is None
    with pytest.raises(AuthError):
        auth.verify(token)


def test_normalized_duplicate_registration_is_atomic_between_workers(tmp_path):
    path = str(tmp_path / "auth.db")
    dbs = (Database(path), Database(path))
    barrier = Barrier(2)

    def register(index):
        barrier.wait()
        try:
            auth_for(dbs[index]).register(
                ("  ADMIN@example.com ", "admin@EXAMPLE.COM")[index],
                "secret",
                "User",
            )
        except DuplicateEmailError:
            return "duplicate"
        return "registered"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(register, range(2)))
    assert sorted(outcomes) == ["duplicate", "registered"]
    assert len(dbs[0].fetchall("SELECT * FROM users")) == 1


def test_additive_migration_preserves_legacy_user_schema_and_credentials(tmp_path):
    path = str(tmp_path / "legacy.db")
    password_hash = hash_password("legacy-secret")
    legacy = (
        "usr-legacy",
        " Legacy@EXAMPLE.com ",
        password_hash,
        "Legacy User",
        "2024-01-01T01:02:03+00:00",
        "retain this field",
    )
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE users (
            user_id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, display_name TEXT NOT NULL,
            created_at TEXT NOT NULL, custom_legacy_field TEXT)""")
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", legacy)
        schema_before = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'users'"
        ).fetchone()[0]

    for _ in range(2):
        db = Database(path)
        assert tuple(db.fetchone("SELECT * FROM users").values()) == legacy
        assert (
            db.fetchone("SELECT sql FROM sqlite_master WHERE name = 'users'")["sql"]
            == schema_before
        )
        auth = auth_for(db)
        token = auth.login("legacy@example.COM", "legacy-secret")
        assert auth.verify(token).user_id == "usr-legacy"
        with pytest.raises(DuplicateEmailError):
            auth.register("legacy@example.com", "another-secret", "Duplicate")
        assert (
            db.fetchone("SELECT password_hash FROM users")["password_hash"]
            == password_hash
        )
    assert db.fetchone("PRAGMA foreign_key_check") is None
    indexes = {row["name"] for row in db.fetchall("PRAGMA index_list(sessions)")}
    assert {"idx_sessions_user", "idx_sessions_expiry"} <= indexes


def test_nested_identity_transaction_rolls_back_with_bootstrap(tmp_path):
    db = Database(str(tmp_path / "auth.db"))
    auth = auth_for(db)

    def failed_bootstrap():
        with db.transaction():
            auth.register("admin@example.com", "secret", "Admin")
            raise ValueError("bootstrap failed")

    with pytest.raises(ValueError, match="bootstrap failed"):
        failed_bootstrap()
    assert db.fetchone("SELECT * FROM users") is None

    with db.transaction():
        user = auth.register("admin@example.com", "secret", "Admin")
        with pytest.raises(DuplicateEmailError):
            auth.register("ADMIN@example.com", "secret", "Duplicate")
    assert SqliteUserStore(db).get(user.user_id) == user
