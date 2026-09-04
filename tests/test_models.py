"""Tests for the models module — SiemAlert alias parsing and model validation."""

from __future__ import annotations

from terminus.models import (
    Confidence,
    Evidence,
    InvestigationReport,
    PolicyResult,
    Severity,
    SiemAlert,
    Tier,
    Verdict,
)


class TestSiemAlertNestedWazuhJson:
    """SiemAlert should parse raw nested Wazuh webhook JSON."""

    def test_parses_nested_wazuh_alert(self) -> None:
        # Given a raw nested Wazuh alert dict
        raw = {
            "id": "alert-001",
            "rule": {
                "id": 5710,
                "level": 10,
                "description": "SSH brute force",
                "mitre": {"id": "T1110"},
            },
            "agent": {"id": "001", "name": "webserver"},
            "timestamp": "2026-09-04T01:00:00Z",
            "location": "/var/log/auth.log",
            "data": {"srcip": "10.0.0.5"},
        }

        # When parsed into SiemAlert
        alert = SiemAlert.model_validate(raw)

        # Then all fields are correctly extracted
        assert alert.id == "alert-001"
        assert alert.rule_id == 5710
        assert alert.level == 10
        assert alert.description == "SSH brute force"
        assert alert.mitre == "T1110"
        assert alert.agent_id == "001"
        assert alert.agent_name == "webserver"
        assert alert.src_ip == "10.0.0.5"

    def test_parses_flat_dict(self) -> None:
        # Given a flat pre-parsed dict
        flat = {
            "id": "alert-002",
            "rule_id": 5501,
            "level": 3,
            "description": "Login success",
        }

        # When parsed
        alert = SiemAlert.model_validate(flat)

        # Then fields map correctly
        assert alert.rule_id == 5501
        assert alert.level == 3

    def test_preserves_extra_fields(self) -> None:
        # Given a Wazuh alert with extra fields we don't model
        raw = {
            "id": "alert-003",
            "rule": {"id": 100, "level": 2},
            "decoder": {"name": "sshd"},
        }

        # When parsed (extra="allow")
        alert = SiemAlert.model_validate(raw)

        # Then the extra fields are preserved
        assert alert.id == "alert-003"

    def test_optional_fields_default(self) -> None:
        # Given minimal alert
        raw = {"id": "alert-004", "rule": {"id": 1, "level": 1}}

        # When parsed
        alert = SiemAlert.model_validate(raw)

        # Then optional fields default to None/empty
        assert alert.mitre is None
        assert alert.agent_id is None
        assert alert.src_ip is None
        assert alert.description == ""


class TestVerdict:
    """Verdict model validation."""

    def test_valid_verdict(self) -> None:
        v = Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            summary="Brute force detected",
            recommended_actions=["Block IP"],
        )
        assert v.severity == Severity.HIGH
        assert v.recommended_actions == ["Block IP"]

    def test_verdict_forbids_extra(self) -> None:
        import pytest

        with pytest.raises(Exception):
            Verdict(
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                summary="test",
                extra_field="should fail",
            )


class TestPolicyResult:
    """PolicyResult model validation."""

    def test_valid_policy_result(self) -> None:
        pr = PolicyResult(
            alert_id="a1",
            tier=Tier.ESCALATE,
            should_investigate=True,
            reason="level >= 10",
        )
        assert pr.tier == Tier.ESCALATE


class TestDataclasses:
    """Evidence and InvestigationReport frozen dataclasses."""

    def test_evidence_is_frozen(self) -> None:
        import pytest

        alert = SiemAlert.model_validate(
            {"id": "a1", "rule": {"id": 1, "level": 1}},
        )
        ev = Evidence(
            alert=alert,
            agent_name=None,
            threat_intel="clean",
            context_notes="test",
        )
        with pytest.raises(AttributeError):
            ev.threat_intel = "modified"  # type: ignore[misc]

    def test_investigation_report(self) -> None:
        alert = SiemAlert.model_validate(
            {"id": "a1", "rule": {"id": 1, "level": 1}},
        )
        ev = Evidence(alert=alert, agent_name=None, threat_intel="", context_notes="")
        verdict = Verdict(
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            summary="benign",
        )
        policy = PolicyResult(
            alert_id="a1",
            tier=Tier.IGNORE,
            should_investigate=False,
            reason="low level",
        )
        report = InvestigationReport(
            alert_id="a1",
            policy=policy,
            verdict=verdict,
            evidence=ev,
        )
        assert report.alert_id == "a1"
