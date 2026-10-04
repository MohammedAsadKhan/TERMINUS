"""Authenticated credential envelopes; master keys never enter SQLite."""

from __future__ import annotations

import base64
import binascii
import secrets
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr


class CredentialProtectionError(ValueError):
    """Safe error with no credential, ciphertext or key details."""


class CredentialCipher:
    __slots__: ClassVar[tuple[str, ...]] = ("_cipher",)

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise CredentialProtectionError("Credential protection is unavailable")
        self._cipher: AESGCM = AESGCM(key)

    @classmethod
    def from_key(cls, key: str) -> CredentialCipher:
        try:
            decoded = base64.b64decode(
                key.encode("ascii"), altchars=b"-_", validate=True
            )
            if base64.urlsafe_b64encode(decoded).decode("ascii") != key:
                raise ValueError
            return cls(decoded)
        except (ValueError, UnicodeError, binascii.Error):
            raise CredentialProtectionError(
                "Credential protection is unavailable"
            ) from None

    @staticmethod
    def generate_key() -> SecretStr:
        return SecretStr(
            base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        )

    @staticmethod
    def _associated_data(binding: str) -> bytes:
        if not binding or len(binding.encode("utf-8")) > 1024:
            raise CredentialProtectionError("Credential protection is unavailable")
        return b"terminus-model-credential:v1:" + binding.encode("utf-8")

    def encrypt(self, secret: str, binding: str) -> str:
        if not secret.strip() or len(secret.encode("utf-8")) > 4096:
            raise CredentialProtectionError("Invalid credential")
        nonce = secrets.token_bytes(12)
        encrypted = self._cipher.encrypt(
            nonce, secret.encode("utf-8"), self._associated_data(binding)
        )
        return "v1." + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")

    def decrypt(self, token: str, binding: str) -> SecretStr:
        try:
            if not token.startswith("v1.") or len(token) > 6000:
                raise ValueError
            payload = base64.b64decode(
                token[3:].encode("ascii"), altchars=b"-_", validate=True
            )
            if len(payload) < 29:
                raise ValueError
            decoded = self._cipher.decrypt(
                payload[:12], payload[12:], self._associated_data(binding)
            ).decode("utf-8")
            if not decoded.strip() or len(decoded.encode("utf-8")) > 4096:
                raise ValueError
            return SecretStr(decoded)
        except (ValueError, UnicodeError, binascii.Error, InvalidTag):
            raise CredentialProtectionError(
                "Credential protection is unavailable"
            ) from None
