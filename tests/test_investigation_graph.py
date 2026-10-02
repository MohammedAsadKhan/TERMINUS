"""Graph evidence survives restart and stays inside the requesting tenant."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from terminus.core.ids import OrgId, RuleId
from terminus.investigation.graph import GraphEventStore
from terminus.models import Confidence, Evidence, InvestigationReport, PolicyResult, Severity, SiemAlert, Tier, Verdict
from terminus.storage.db import Database


def _report(alert: SiemAlert) -> InvestigationReport:
    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(alert_id=alert.id, tier=Tier.ESCALATE, should_investigate=True, reason="Test"),
        verdict=Verdict(severity=Severity.HIGH, confidence=Confidence.HIGH, summary="Observed attack attempt"),
        evidence=Evidence(alert=alert, agent_name=alert.agent_name, threat_intel="Unknown", context_notes=""),
    )


def test_graph_persists_exact_evidence_and_is_tenant_scoped(tmp_path) -> None:
    path = str(tmp_path / "events.db")
    store = GraphEventStore(Database(path))
    now = datetime.now(UTC)
    first = SiemAlert(id="a-1", rule_id=RuleId(100), level=12, description="Exploit probe", agent_name="web-01", src_ip="203.0.113.77", full_log="GET /search?q=probe", timestamp=now.isoformat(), mitre="T1190")
    second = SiemAlert(id="a-2", rule_id=RuleId(101), level=8, description="SSH failures", agent_name="auth-01", src_ip="203.0.113.77", full_log="37 failed passwords", timestamp=now.isoformat(), mitre="T1110")
    other = SiemAlert(id="b-1", rule_id=RuleId(102), level=10, description="Other tenant", agent_name="private-01", src_ip="198.51.100.5", full_log="private evidence", timestamp=now.isoformat())
    store.record(first, OrgId("org-a"), _report(first), "TICK-1")
    store.record(second, OrgId("org-a"), _report(second), "TICK-2")
    store.record(other, OrgId("org-b"), _report(other), "TICK-3")
    store.record(first, OrgId("org-a"), _report(first), "TICK-1")  # duplicate alert is idempotent

    reopened = GraphEventStore(Database(path))
    start = (now - timedelta(days=7)).isoformat()
    end = (now + timedelta(seconds=1)).isoformat()
    graph = reopened.snapshot(OrgId("org-a"), start, end)
    assert graph["total_events"] == 2
    assert len(graph["edges"]) == 2
    assert {node["label"] for node in graph["nodes"] if node["kind"] == "host"} == {"web-01", "auth-01"}
    evidence = reopened.evidence(OrgId("org-a"), start, end, source_ip="203.0.113.77")
    assert evidence["total"] == 2
    assert {event["raw_event"] for event in evidence["events"]} == {"GET /search?q=probe", "37 failed passwords"}
    assert reopened.snapshot(OrgId("org-b"), start, end)["total_events"] == 1
    assert reopened.evidence(OrgId("org-a"), start, end, source_ip="198.51.100.5")["total"] == 0
