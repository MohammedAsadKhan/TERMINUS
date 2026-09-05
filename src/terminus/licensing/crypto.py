from __future__ import annotations

import base64
import hashlib
import hmac
import json

from terminus.licensing.models import License


class LicenseError(ValueError):
    """Error raised when license validation fails."""

    def __init__(self, message: str, reason: str = "invalid") -> None:
        super().__init__(message)
        self.reason = reason


def canonical_bytes(license_obj: License) -> bytes:
    """Serialize license to deterministic JSON bytes."""
    data = license_obj.model_dump(mode="json")
    # Features must be sorted
    data["features"] = sorted(data["features"])
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign(canonical: bytes, secret: str) -> str:
    """Generate HMAC-SHA256 signature for canonical bytes."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()


def encode(license_obj: License, secret: str) -> str:
    """Encode license into signed token string."""
    canonical = canonical_bytes(license_obj)
    signature = sign(canonical, secret)

    encoded_data = base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=")
    encoded_sig = (
        base64.urlsafe_b64encode(signature.encode("ascii")).decode("ascii").rstrip("=")
    )

    return f"{encoded_data}.{encoded_sig}"


def decode(raw: str, secret: str) -> License:
    """Decode and verify signed license token."""
    parts = raw.split(".")
    if len(parts) != 2:
        raise LicenseError("Invalid license format", reason="malformed")

    encoded_data, encoded_sig = parts

    try:
        # Add padding back if necessary
        canonical = base64.urlsafe_b64decode(
            encoded_data + "=" * (-len(encoded_data) % 4)
        )
        signature = base64.urlsafe_b64decode(
            encoded_sig + "=" * (-len(encoded_sig) % 4)
        ).decode("ascii")
    except Exception as e:
        raise LicenseError("Invalid base64 encoding", reason="bad_encoding") from e

    expected_signature = sign(canonical, secret)
    if not hmac.compare_digest(signature, expected_signature):
        raise LicenseError("Signature mismatch", reason="tampered")

    try:
        data = json.loads(canonical)
        return License.model_validate(data)
    except Exception as e:
        raise LicenseError("Invalid license payload", reason="bad_payload") from e
