from __future__ import annotations

import pytest

from terminus.auth.password import hash_password, verify_password
from terminus.auth.service import AuthError, AuthService, DuplicateEmailError, UserStore


def test_password_hashing():
    # Given
    password = "supersecretpassword123!"

    # When
    hashed = hash_password(password)

    # Then
    assert hashed.startswith("pbkdf2$sha256$210000$")
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False
    assert verify_password(password, "malformed_hash") is False
    assert verify_password(password, "pbkdf2$sha256$210000$invalidhex$hash") is False


def test_auth_service_register_and_login():
    # Given
    store = UserStore()
    service = AuthService(store)

    # When
    user = service.register("test@example.com", "mypass", "Test User")
    token = service.login("test@example.com", "mypass")
    verified_user = service.verify(token)

    # Then
    assert user.email == "test@example.com"
    assert user.display_name == "Test User"
    assert verified_user.user_id == user.user_id
    assert token.startswith("tok-")
    assert user.user_id.startswith("usr-")


def test_auth_service_duplicate_email():
    # Given
    store = UserStore()
    service = AuthService(store)
    service.register("test@example.com", "mypass", "Test User")

    # When / Then
    with pytest.raises(DuplicateEmailError):
        service.register("TEST@example.com", "anotherpass", "Another User")


def test_auth_service_bad_login():
    # Given
    store = UserStore()
    service = AuthService(store)
    service.register("test@example.com", "mypass", "Test User")

    # When / Then
    with pytest.raises(AuthError):
        service.login("test@example.com", "wrongpass")

    with pytest.raises(AuthError):
        service.login("nonexistent@example.com", "mypass")


def test_auth_service_logout():
    # Given
    store = UserStore()
    service = AuthService(store)
    service.register("test@example.com", "mypass", "Test User")
    token = service.login("test@example.com", "mypass")

    # When
    service.logout(token)

    # Then
    with pytest.raises(AuthError):
        service.verify(token)
