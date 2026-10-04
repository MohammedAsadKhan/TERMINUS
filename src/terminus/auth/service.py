from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Protocol

from terminus.auth.models import User
from terminus.auth.password import hash_password, verify_password
from terminus.core.base import Service
from terminus.core.ids import UserId


class AuthError(ValueError):
    """General authentication error."""


class DuplicateEmailError(ValueError):
    """Email already registered."""


SessionToken = str


def normalize_email(email: str) -> str:
    """Use the same identity key for registration and lookup."""
    return email.strip().lower()


@dataclass(frozen=True)
class Session:
    user_id: UserId
    expires_at: datetime


class SessionStore(Protocol):
    """Session persistence receives token digests, never bearer tokens."""

    def add(self, token_hash: str, user_id: UserId, expires_at: datetime) -> None: ...

    def get(self, token_hash: str) -> Session | None: ...

    def revoke(self, token_hash: str) -> None: ...


class MemorySessionStore:
    """Session backend for callers that explicitly use in-memory identity."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock: threading.Lock = threading.Lock()

    def add(self, token_hash: str, user_id: UserId, expires_at: datetime) -> None:
        with self._lock:
            self._sessions[token_hash] = Session(user_id, expires_at)

    def get(self, token_hash: str) -> Session | None:
        with self._lock:
            return self._sessions.get(token_hash)

    def revoke(self, token_hash: str) -> None:
        with self._lock:
            _ = self._sessions.pop(token_hash, None)


class UserStore:
    """Platform-wide user store."""

    def __init__(self) -> None:
        self._users: dict[UserId, User] = {}
        self._email_idx: dict[str, UserId] = {}
        self._lock: threading.Lock = threading.Lock()

    def add(self, user: User) -> None:
        email = normalize_email(user.email)
        with self._lock:
            if email in self._email_idx:
                raise DuplicateEmailError(f"Email {user.email} already exists")
            self._users[user.user_id] = user
            self._email_idx[email] = user.user_id

    def get_by_email(self, email: str) -> User | None:
        with self._lock:
            user_id = self._email_idx.get(normalize_email(email))
            if user_id is None:
                return None
            return self._users.get(user_id)

    def get(self, user_id: UserId) -> User | None:
        with self._lock:
            return self._users.get(user_id)


class AuthService(Service):
    """Service handling authentication."""

    def __init__(
        self, user_store: UserStore, session_store: SessionStore | None = None
    ) -> None:
        self._user_store: UserStore = user_store
        self._session_store: SessionStore = (
            session_store if session_store is not None else MemorySessionStore()
        )

    def register(self, email: str, password: str, display_name: str) -> User:
        """Register a new user."""
        email = normalize_email(email)
        if "@" not in email or "." not in email:
            raise ValueError("Invalid email format")

        user_id = UserId("usr-" + secrets.token_urlsafe(8).rstrip("="))
        user = User(
            user_id=user_id,
            email=email,
            password_hash=hash_password(password),
            display_name=display_name,
            created_at=datetime.now(UTC),
        )
        self._user_store.add(user)
        return user

    def login(self, email: str, password: str) -> SessionToken:
        """Log in a user, returning a session token."""
        user = self._user_store.get_by_email(email)
        if user is None:
            raise AuthError("Invalid email or password")

        if not verify_password(password, user.password_hash):
            raise AuthError("Invalid email or password")

        token = SessionToken("tok-" + secrets.token_urlsafe(24).rstrip("="))
        self._session_store.add(
            self._token_hash(token),
            user.user_id,
            datetime.now(UTC) + timedelta(hours=12),
        )
        return token

    def verify(self, token: SessionToken) -> User:
        """Verify a session token and return the User."""
        token_hash = self._token_hash(token)
        session = self._session_store.get(token_hash)
        if session is None:
            raise AuthError("Invalid or expired session")
        if session.expires_at <= datetime.now(UTC):
            self._session_store.revoke(token_hash)
            raise AuthError("Invalid or expired session")

        user = self._user_store.get(session.user_id)
        if user is None:
            raise AuthError("User no longer exists")

        return user

    def logout(self, token: SessionToken) -> None:
        """Revoke a session across every caller sharing its backend."""
        self._session_store.revoke(self._token_hash(token))

    @staticmethod
    def _token_hash(token: SessionToken) -> str:
        return sha256(token.encode("utf-8")).hexdigest()
