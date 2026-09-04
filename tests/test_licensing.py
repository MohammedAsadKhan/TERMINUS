from __future__ import annotations

import base64
import json

import pytest

from terminus.core.ids import OrgId
from terminus.licensing.crypto import (
    LicenseError,
    decode,
    sign,
)
from terminus.licensing.models import Feature, LicenseTier
from terminus.licensing.service import LicenseService


@pytest.fixture
def secret() -> str:
    return "test-secret-key-123"


@pytest.fixture
def service(secret: str) -> LicenseService:
    return LicenseService(secret=secret)


@pytest.fixture
def org_id() -> OrgId:
    return OrgId("org_123")


def test_round_trip_encode_decode(service: LicenseService, org_id: OrgId) -> None:
    """Test generating a license and validating it successfully."""
    # Given a generated license token
    token = service.generate(org_id, LicenseTier.PRO, seats=10)

    # When validating it
    license_obj = service.validate(token)

    # Then it should parse successfully with correct properties
    assert license_obj.org_id == org_id
    assert license_obj.tier == LicenseTier.PRO
    assert license_obj.seats == 10
    assert Feature.API_ACCESS in license_obj.features


def test_tamper_detection(service: LicenseService, org_id: OrgId) -> None:
    """Test that modifying the payload without updating the signature fails validation."""
    # Given a valid license token
    token = service.generate(org_id, LicenseTier.FREE, seats=1)

    # When we tamper with the payload but keep the signature
    parts = token.split(".")
    payload = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
    data = json.loads(payload)

    data["tier"] = LicenseTier.ENTERPRISE.value
    data["seats"] = 1000

    tampered_payload = (
        base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    )
    tampered_token = f"{tampered_payload}.{parts[1]}"

    # Then validation should fail
    with pytest.raises(LicenseError) as exc:
        service.validate(tampered_token)

    assert exc.value.reason == "tampered"


def test_expiry_checking(service: LicenseService, org_id: OrgId) -> None:
    """Test that validating an expired license fails."""
    # Given an expired license (generated with negative duration)
    token = service.generate(org_id, LicenseTier.FREE, seats=1, duration_days=-1)

    # When validating it
    # Then it should fail with expired reason
    with pytest.raises(LicenseError) as exc:
        service.validate(token)

    assert exc.value.reason == "expired"


def test_feature_entitlement(service: LicenseService, org_id: OrgId) -> None:
    """Test feature entitlement checks for different tiers."""
    # Given different licenses
    free_token = service.generate(org_id, LicenseTier.FREE, seats=1)
    pro_token = service.generate(org_id, LicenseTier.PRO, seats=5)

    free_license = service.validate(free_token)
    pro_license = service.validate(pro_token)

    # Then entitlements should match the tier mapping
    assert not service.entitled(free_license, Feature.API_ACCESS)
    assert service.entitled(pro_license, Feature.API_ACCESS)
    assert not service.entitled(pro_license, Feature.SSO)


def test_tier_mapping_seat_limits(service: LicenseService, org_id: OrgId) -> None:
    """Test that generating a license with too many seats fails."""
    # Given an attempt to generate a license with too many seats
    # When/Then it should raise ValueError
    with pytest.raises(ValueError, match="exceeds maximum"):
        service.generate(org_id, LicenseTier.FREE, seats=10)

    # But should succeed within limits
    service.generate(org_id, LicenseTier.FREE, seats=5)


def test_decode_malformed_token(service: LicenseService) -> None:
    """Test decoding a malformed token."""
    with pytest.raises(LicenseError) as exc:
        service.validate("not-a-valid-token")
    assert exc.value.reason == "malformed"


def test_decode_bad_encoding(service: LicenseService) -> None:
    """Test decoding a token with invalid base64 encoding."""
    with pytest.raises(LicenseError) as exc:
        service.validate("invalid_base64_data!!!.invalid_base64_sig!!!")
    assert exc.value.reason == "bad_encoding"


def test_decode_bad_payload(secret: str, org_id: OrgId) -> None:
    """Test decoding a token with a valid signature but bad JSON payload."""
    # Create valid base64 but invalid JSON
    bad_json = b"not-json"
    signature = sign(bad_json, secret)

    encoded_data = base64.urlsafe_b64encode(bad_json).decode("ascii").rstrip("=")
    encoded_sig = (
        base64.urlsafe_b64encode(signature.encode("ascii")).decode("ascii").rstrip("=")
    )

    bad_token = f"{encoded_data}.{encoded_sig}"

    with pytest.raises(LicenseError) as exc:
        decode(bad_token, secret)
    assert exc.value.reason == "bad_payload"
