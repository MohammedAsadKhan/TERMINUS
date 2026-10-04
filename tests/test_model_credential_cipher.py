"""Credential encryption boundary regression tests."""

from __future__ import annotations

import pytest

from terminus.config import Settings
from terminus.model_gateway.secrets import CredentialCipher, CredentialProtectionError


def test_encryption_is_random_and_bound_to_connection() -> None:
    key = CredentialCipher.generate_key()
    cipher = CredentialCipher.from_key(key.get_secret_value())
    first = cipher.encrypt("sensitive-test-api-key", '["org-a","connection-a"]')
    second = cipher.encrypt("sensitive-test-api-key", '["org-a","connection-a"]')
    assert first != second
    assert "sensitive-test-api-key" not in first
    assert (
        cipher.decrypt(first, '["org-a","connection-a"]').get_secret_value()
        == "sensitive-test-api-key"
    )
    with pytest.raises(CredentialProtectionError):
        cipher.decrypt(first, '["org-b","connection-a"]')
    other = CredentialCipher.from_key(
        CredentialCipher.generate_key().get_secret_value()
    )
    with pytest.raises(CredentialProtectionError):
        other.decrypt(first, '["org-a","connection-a"]')


@pytest.mark.parametrize(
    "key", ["", "password", "key-value-should-not-be-echoed", "🤫", "A" * 44]
)
def test_invalid_master_key_fails_without_echo(key: str) -> None:
    with pytest.raises(CredentialProtectionError) as error:
        CredentialCipher.from_key(key)
    assert str(error.value) == "Credential protection is unavailable"


@pytest.mark.parametrize("token", ["", "v2.invalid", "v1.invalid", "v1." + "A" * 7000])
def test_malformed_ciphertext_is_safe(token: str) -> None:
    cipher = CredentialCipher.from_key(
        CredentialCipher.generate_key().get_secret_value()
    )
    with pytest.raises(CredentialProtectionError):
        cipher.decrypt(token, "org/connection")


def test_settings_does_not_serialize_or_repr_master_key() -> None:
    key = CredentialCipher.generate_key().get_secret_value()
    settings = Settings(_env_file=None, model_credentials_key=key)
    assert key not in repr(settings)
    assert key not in settings.model_dump_json()
    assert "model_credentials_key" not in settings.model_dump()
