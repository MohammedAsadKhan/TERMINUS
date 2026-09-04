from __future__ import annotations

import hashlib
import hmac
import secrets

ITERATIONS = 210000
ALGO = "sha256"
PREFIX = f"pbkdf2${ALGO}${ITERATIONS}$"


def hash_password(plain: str, salt: bytes | None = None) -> str:
    """Hash a plain text password."""
    if salt is None:
        salt = secrets.token_bytes(16)

    dk = hashlib.pbkdf2_hmac(ALGO, plain.encode("utf-8"), salt, ITERATIONS)
    return f"{PREFIX}{salt.hex()}${dk.hex()}"


def verify_password(plain: str, stored: str) -> bool:
    """Verify a plain text password against a stored hash."""
    if not stored.startswith(PREFIX):
        return False

    parts = stored.split("$")
    if len(parts) != 5:
        return False

    try:
        salt_hex = parts[3]
        hash_hex = parts[4]
        salt = bytes.fromhex(salt_hex)
        stored_dk = bytes.fromhex(hash_hex)
    except ValueError:
        return False

    dk = hashlib.pbkdf2_hmac(ALGO, plain.encode("utf-8"), salt, ITERATIONS)
    return hmac.compare_digest(dk, stored_dk)
