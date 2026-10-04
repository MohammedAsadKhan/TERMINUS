"""SQLite identity adapters backed by the platform's configured database."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import override

from terminus.auth.models import User
from terminus.auth.service import (
    DuplicateEmailError,
    Session,
    UserStore,
    normalize_email,
)
from terminus.core.ids import UserId
from terminus.storage.db import Database


class SqliteUserStore(UserStore):
    """Persist identities without copying or rehashing their password hashes."""

    def __init__(self, db: Database) -> None:
        super().__init__()
        self._db: Database = db

    @override
    def add(self, user: User) -> None:
        email = normalize_email(user.email)
        # The writer lock makes the normalized lookup and insert atomic across
        # workers, including databases whose existing emails use mixed case.
        with self._db.transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM users WHERE lower(trim(email)) = ? LIMIT 1", (email,)
            ).fetchone():
                raise DuplicateEmailError(f"Email {email} already exists")
            try:
                _ = conn.execute(
                    """INSERT INTO users
                       (user_id, email, password_hash, display_name, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        str(user.user_id),
                        email,
                        user.password_hash,
                        user.display_name,
                        user.created_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                # Translate only the email constraint; unrelated corruption or
                # colliding user IDs must not be reported as duplicate emails.
                if "users.email" in str(exc):
                    raise DuplicateEmailError(f"Email {email} already exists") from exc
                raise

    @override
    def get_by_email(self, email: str) -> User | None:
        row = self._db.fetchone(
            """SELECT * FROM users WHERE lower(trim(email)) = ?
               ORDER BY created_at, user_id LIMIT 1""",
            (normalize_email(email),),
        )
        return self._user(row)

    @override
    def get(self, user_id: UserId) -> User | None:
        return self._user(
            self._db.fetchone("SELECT * FROM users WHERE user_id = ?", (str(user_id),))
        )

    @staticmethod
    def _user(row: Mapping[str, object] | None) -> User | None:
        if row is None:
            return None
        return User(
            user_id=UserId(str(row["user_id"])),
            email=str(row["email"]),
            password_hash=str(row["password_hash"]),
            display_name=str(row["display_name"]),
            created_at=datetime.fromisoformat(str(row["created_at"])),
        )


class SqliteSessionStore:
    """Persist token digests, UTC expiry, and revocation across restarts."""

    def __init__(self, db: Database) -> None:
        self._db: Database = db

    def add(self, token_hash: str, user_id: UserId, expires_at: datetime) -> None:
        _ = self._db.execute(
            """INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (
                token_hash,
                str(user_id),
                datetime.now(UTC).isoformat(),
                expires_at.astimezone(UTC).isoformat(),
            ),
        )

    def get(self, token_hash: str) -> Session | None:
        row: Mapping[str, object] | None = self._db.fetchone(
            """SELECT user_id, expires_at FROM sessions
               WHERE token_hash = ? AND revoked_at IS NULL""",
            (token_hash,),
        )
        if row is None:
            return None
        return self._session(row)

    @staticmethod
    def _session(row: Mapping[str, object]) -> Session:
        expires_at = datetime.fromisoformat(str(row["expires_at"]))
        return Session(UserId(str(row["user_id"])), expires_at)

    def revoke(self, token_hash: str) -> None:
        _ = self._db.execute(
            """UPDATE sessions SET revoked_at = ?
               WHERE token_hash = ? AND revoked_at IS NULL""",
            (datetime.now(UTC).isoformat(), token_hash),
        )
