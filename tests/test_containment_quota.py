"""Unit tests for Fleet-Wide Containment Quota and Blast Radius Lease Guardrails."""

from __future__ import annotations

from terminus.containment.guardrails import ContainmentGuardrail, FleetContainmentQuota


def setup_function() -> None:
    FleetContainmentQuota.reset()


def test_fleet_containment_quota_sliding_window() -> None:
    org_id = "org-quota-test"
    target_subnet = "192.168.1.10"

    # Up to 3 isolations allowed per /24 subnet
    allowed_1, reason_1 = FleetContainmentQuota.record_and_check(org_id, target_subnet)
    assert allowed_1 is True
    assert reason_1 is None

    allowed_2, _ = FleetContainmentQuota.record_and_check(org_id, "192.168.1.11")
    assert allowed_2 is True

    allowed_3, _ = FleetContainmentQuota.record_and_check(org_id, "192.168.1.12")
    assert allowed_3 is True

    # 4th isolation in the same /24 subnet exceeds the 3-host limit
    allowed_4, reason_4 = FleetContainmentQuota.record_and_check(org_id, "192.168.1.13")
    assert allowed_4 is False
    assert "Subnet containment quota exceeded" in str(reason_4)


def test_blast_radius_assessment_lease_ttl() -> None:
    assessment = ContainmentGuardrail.assess_target("workstation-test-01.corp", kind="host")
    assert assessment.allowed is True
    assert assessment.ttl_seconds == 1800
    assert assessment.expires_at is not None
    assert "T" in assessment.expires_at
