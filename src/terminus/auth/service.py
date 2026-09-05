from __future__ import annotations

import secrets
import threading
from datetime import UTC, datetime, timedelta

from terminus.auth.models import User
from terminus.auth.password import hash_password, verify_password
from terminus.core.base import Service
from terminus.core.ids import UserId


class AuthError(ValueError):
    """General authentication error."""


class DuplicateEmailError(ValueError):
    """Email already registered."""


SessionToken = str


class UserStore:
    """Platform-wide user store."""

    def __init__(self) -> None:
        self._users: dict[UserId, User] = {}
        self._email_idx: dict[str, UserId] = {}
        self._lock = threading.Lock()

    def add(self, user: User) -> None:
        with self._lock:
            if user.email in self._email_idx:
                raise DuplicateEmailError(f"Email {user.email} already exists")
            self._users[user.user_id] = user
            self._email_idx[user.email] = user.user_id

    def get_by_email(self, email: str) -> User | None:
        with self._lock:
            user_id = self._email_idx.get(email.lower())
            if user_id is None:
                return None
            return self._users.get(user_id)

    def get(self, user_id: UserId) -> User | None:
        with self._lock:
            return self._users.get(user_id)


class AuthService(Service):
    """Service handling authentication."""

    def __init__(self, user_store: UserStore) -> None:
        self._user_store = user_store
        self._sessions: dict[SessionToken, UserId] = {}
        self._expires: dict[SessionToken, datetime] = {}
        self._lock = threading.Lock()

    def register(self, email: str, password: str, display_name: str) -> User:
        """Register a new user."""
        email = email.lower()
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
        with self._lock:
            self._sessions[token] = user.user_id
            self._expires[token] = datetime.now(UTC) + timedelta(hours=12)
        return token

    def verify(self, token: SessionToken) -> User:
        """Verify a session token and return the User."""
        with self._lock:
            user_id = self._sessions.get(token)
            expiry = self._expires.get(token)
            if expiry is None or expiry <= datetime.now(UTC):
                self._sessions.pop(token, None)
                self._expires.pop(token, None)
                user_id = None

        if user_id is None:
            raise AuthError("Invalid or expired session")

        user = self._user_store.get(user_id)
        if user is None:
            raise AuthError("User no longer exists")

        return user

    def logout(self, token: SessionToken) -> None:
        """Log out a user by removing their session."""
        with self._lock:
            self._sessions.pop(token, None)
            self._expires.pop(token, None)
