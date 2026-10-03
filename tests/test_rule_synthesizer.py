"""Unit tests for Dynamic Sigma & YARA Rule Synthesizer and Wilson Score Engine."""

from __future__ import annotations

from terminus.models import Confidence, Evidence, InvestigationReport, PolicyResult, Severity, SiemAlert, Tier, Verdict
from terminus.tuning.metrics import calculate_wilson_score_interval, evaluate_rule_statistical_precision
from terminus.tuning.synthesizer import RuleSeverity, RuleSynthesizer


def test_wilson_score_interval_bounds() -> None:
    # 95 successes out of 100
    lower, upper = calculate_wilson_score_interval(95, 100, confidence=0.95)
    assert 0.88 <= lower <= 0.92
    assert 0.97 <= upper <= 0.99
    assert lower < 0.95 < upper

    # Edge cases
    assert calculate_wilson_score_interval(0, 0) == (0.0, 0.0)
    assert calculate_wilson_score_interval(0, 100)[0] == 0.0


def test_evaluate_rule_statistical_precision() -> None:
    stats = evaluate_rule_statistical_precision(
        historical_tp=90,
        historical_fp=10,
        total_historical_events=5000,
        min_wlb_threshold=0.80,
    )
    assert stats.observed_precision == 0.9
    assert stats.wilson_lower_bound_precision >= 0.80
    assert stats.is_statistically_sound is True


def test_synthesize_sigma_rule() -> None:
    alert = SiemAlert(
        id="alt-test-01",
        rule_id=100050,
        level=14,
        description="PowerShell Encoded Script Execution",
        mitre="T1059.001",
        agent_name="workstation-99.corp.internal",
        full_log="powershell.exe -NoProfile -enc SQBFAFgA",
    )
    report = InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(alert_id=alert.id, tier=Tier.ESCALATE, should_investigate=True, reason="Critical"),
        verdict=Verdict(
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            summary="Confirmed obfuscated PowerShell dropper payload.",
            recommended_actions=["Isolate endpoint", "Kill process"],
        ),
        evidence=Evidence(
            alert=alert,
            agent_name="workstation-99.corp.internal",
            threat_intel="Malicious",
            context_notes="Obfuscated script executed",
        ),
    )

    sigma = RuleSynthesizer.synthesize_sigma_rule(alert, report)
    assert "PowerShell" in sigma.title
    assert sigma.level == RuleSeverity.CRITICAL
    assert "attack.t1059_001" in sigma.tags
    assert sigma.detection["selection"]["Image|endswith"] == ["workstation-99.corp.internal"]

    yaml_output = sigma.to_yaml()
    assert "logsource:" in yaml_output
    assert "process_creation" in yaml_output
    assert "detection:" in yaml_output


def test_synthesize_yara_rule() -> None:
    alert = SiemAlert(
        id="alt-test-02",
        rule_id=100060,
        level=12,
        description="Cobalt Strike Beacon Ingress",
        src_ip="198.51.100.77",
        full_log="Payload hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f from 198.51.100.77",
    )
    yara = RuleSynthesizer.synthesize_yara_rule(alert)
    assert "TERMINUS_AUTORULE" in yara.rule_name
    source = yara.to_yara_source()
    assert "rule " in source
    assert "strings:" in source
    assert "condition:" in source
    assert "198.51.100.77" in source
