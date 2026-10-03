import pytest
from pathlib import Path

from terminus.models import SiemAlert, PolicyResult, Verdict, Evidence, InvestigationReport, Severity, Confidence, Tier
from terminus.privacy.redactor import SecretRedactor
from terminus.server.streaming import EventBroadcaster
from terminus.storage.db import create_connection, init_db


def test_models_to_dict_from_dict():
    alert = SiemAlert(
        id="alert-123",
        rule_id=5710,
        level=7,
        description="SSH brute force attempt",
        agent_id="001",
        agent_name="db-prod-01",
        src_ip="192.168.1.50",
        full_log="Failed password for root",
    )
    policy = PolicyResult(
        alert_id="alert-123",
        tier=Tier.TRIAGE,
        should_investigate=True,
        reason="Medium severity alert",
    )
    verdict = Verdict(
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        summary="Brute force detected",
        recommended_actions=["Block IP", "Notify analyst"],
    )
    evidence = Evidence(
        alert=alert,
        agent_name="db-prod-01",
        threat_intel="IP known malicious",
        context_notes="3 failed attempts in 1 minute",
    )
    report = InvestigationReport(
        alert_id="alert-123",
        policy=policy,
        verdict=verdict,
        evidence=evidence,
        campaign_id="camp-1",
        campaign_alert_count=5,
    )

    d = report.to_dict()
    assert isinstance(d, dict)
    assert d["alert_id"] == "alert-123"
    assert d["policy"]["tier"] == "triage"
    assert d["verdict"]["severity"] == "high"
    assert d["evidence"]["alert"]["id"] == "alert-123"

    restored = InvestigationReport.from_dict(d)
    assert restored.alert_id == report.alert_id
    assert restored.policy.tier == report.policy.tier
    assert restored.verdict.severity == report.verdict.severity
    assert restored.evidence.alert.id == report.evidence.alert.id
    assert restored.campaign_id == "camp-1"
    assert restored.campaign_alert_count == 5


def test_db_pragmas_and_tables(tmp_path: Path):
    db_path = tmp_path / "terminus_test.db"
    init_db(db_path)

    conn = create_connection(db_path)
    cur = conn.cursor()

    # Verify foreign_keys
    cur.execute("PRAGMA foreign_keys")
    assert cur.fetchone()[0] == 1

    # Verify journal_mode is WAL
    cur.execute("PRAGMA journal_mode")
    assert cur.fetchone()[0].upper() == "WAL"

    # Verify tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cur.fetchall()}
    expected_tables = {
        "soc_agents",
        "workflows",
        "alert_claims",
        "workflow_runs",
        "node_runs",
        "workflow_approvals",
        "containment_allowlist",
    }
    assert expected_tables.issubset(tables)

    # Verify column migrations exist on workflow_runs (outcome, definition_snapshot, heartbeat_at)
    cur.execute("PRAGMA table_info(workflow_runs)")
    cols = {row[1] for row in cur.fetchall()}
    assert "outcome" in cols
    assert "definition_snapshot" in cols
    assert "heartbeat_at" in cols
    conn.close()


def test_redactor_keys_and_values():
    redactor = SecretRedactor()
    raw = {
        "api_key": "secret-12345",
        "Authorization": "Bearer tok_1234567890abcdef1234567890abcdef",
        "nested": {
            "password": "supersecretpassword",
            "safe_key": "ghp_123456789012345678901234567890123456",
            "normal_value": "hello world",
        },
        "list_data": [
            {"user_secret": "sensitive", "count": 42, "flag": True, "empty": None},
            "wazuh_jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature123456789012",
        ],
    }

    redacted = redactor.redact_dict(raw)
    assert redacted["api_key"] == "[REDACTED]"
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["nested"]["password"] == "[REDACTED]"
    assert redacted["nested"]["safe_key"] == "[REDACTED_GITHUB_TOKEN]"
    assert redacted["nested"]["normal_value"] == "hello world"
    assert redacted["list_data"][0]["user_secret"] == "[REDACTED]"
    assert redacted["list_data"][0]["count"] == 42
    assert redacted["list_data"][0]["flag"] is True
    assert redacted["list_data"][0]["empty"] is None
    assert "[REDACTED_JWT_TOKEN]" in redacted["list_data"][1] or "[REDACTED]" in redacted["list_data"][1]


@pytest.mark.asyncio
async def test_sse_tenant_isolation_and_redaction():
    broadcaster = EventBroadcaster()
    q_org1 = broadcaster.subscribe("org-1")
    q_org2 = broadcaster.subscribe("org-2")

    payload_org1 = {
        "run_id": "run-1",
        "api_key": "top-secret-key-123",
        "data": "safe-data",
    }

    await broadcaster.broadcast_to_org("org-1", "workflow_run_started", payload_org1)

    # org-1 queue should have the message, redacted
    msg1 = await q_org1.get()
    assert msg1["event"] == "workflow_run_started"
    assert msg1["data"]["run_id"] == "run-1"
    assert msg1["data"]["api_key"] == "[REDACTED]"
    assert msg1["data"]["data"] == "safe-data"

    # org-2 queue should be empty
    assert q_org2.empty()

    broadcaster.unsubscribe(q_org1, "org-1")
    broadcaster.unsubscribe(q_org2, "org-2")
