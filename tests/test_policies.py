from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import SiemAlert, Tier
from terminus.policies.engine import PolicyEngine


def test_policy_engine_ignore() -> None:
    # Given
    engine = PolicyEngine()
    alert = SiemAlert.model_validate({"id": "1", "rule": {"id": 1, "level": 3}})
    org_id = OrgId("org-1")

    # When
    result = engine.evaluate(alert, org_id)

    # Then
    assert result.tier == Tier.IGNORE
    assert not result.should_investigate


def test_policy_engine_triage() -> None:
    # Given
    engine = PolicyEngine()
    alert = SiemAlert.model_validate({"id": "2", "rule": {"id": 2, "level": 6}})
    org_id = OrgId("org-1")

    # When
    result = engine.evaluate(alert, org_id)

    # Then
    assert result.tier == Tier.TRIAGE
    assert result.should_investigate


def test_policy_engine_escalate_level() -> None:
    # Given
    engine = PolicyEngine()
    alert = SiemAlert.model_validate({"id": "3", "rule": {"id": 3, "level": 12}})
    org_id = OrgId("org-1")

    # When
    result = engine.evaluate(alert, org_id)

    # Then
    assert result.tier == Tier.ESCALATE
    assert result.should_investigate


def test_policy_engine_escalate_mitre() -> None:
    # Given
    engine = PolicyEngine()
    alert = SiemAlert.model_validate(
        {"id": "4", "rule": {"id": 4, "level": 3, "mitre": {"id": "T1001"}}}
    )
    org_id = OrgId("org-1")

    # When
    result = engine.evaluate(alert, org_id)

    # Then
    assert result.tier == Tier.ESCALATE
    assert result.should_investigate
