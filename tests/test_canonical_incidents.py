"""Canonical incident admission, legacy upgrades, and restart safety."""

import asyncio
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from terminus.core.base import ConflictError, NotFoundError
from terminus.models import (
    Confidence, Evidence, InvestigationReport, PolicyResult, Severity,
    SiemAlert, Tier, Verdict,
)
from terminus.storage.db import Database
from terminus.storage.repositories import SqliteAlertClaimRepository, SqliteIncidentRepository, SqliteWorkflowRunRepository


@pytest.fixture(autouse=True)
def forbid_default_database(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Canonical incident tests must inject a temporary database")
    monkeypatch.setattr(Database, "get_instance", forbidden)


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "canonical.db"))
    yield database
    database._get_connection().close()


@pytest.fixture
def report():
    alert = SiemAlert(id="same-alert", rule_id=123, level=12, agent_name="test-host")
    return InvestigationReport(
        alert_id=alert.id,
        policy=PolicyResult(alert_id=alert.id, tier=Tier.TRIAGE, should_investigate=True, reason="test"),
        verdict=Verdict(severity=Severity.HIGH, confidence=Confidence.HIGH, summary="Initial assessment"),
        evidence=Evidence(alert=alert, agent_name=alert.agent_name, threat_intel="test", context_notes="test"),
        evidence_citations=[{"source": "test", "evidence_id": "ev-1"}],
    )


def test_concurrent_duplicate_admission_separate_connections_and_restart(db, report):
    barrier = threading.Barrier(12)

    def submit():
        # Thread-local connections genuinely race against the same on-disk DB.
        db._get_connection()
        try:
            barrier.wait(timeout=15)
            return asyncio.run(SqliteIncidentRepository(db).create_ticket(report, "tenant-a"))
        finally:
            db._get_connection().close()

    with ThreadPoolExecutor(max_workers=12) as pool:
        ids = list(pool.map(lambda _: submit(), range(12)))
    assert len(set(ids)) == 1
    assert db.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 1
    assert db.fetchone("SELECT COUNT(*) AS n FROM incident_alert_links")["n"] == 1
    db._get_connection().close()
    db._local.conn = None
    reopened = Database(db.db_path)
    try:
        store = SqliteIncidentRepository(reopened)
        assert asyncio.run(store.create_ticket(report, "tenant-a")) == ids[0]
        incident = asyncio.run(store.get_by_alert(report.alert_id, "tenant-a"))
        assert incident["id"] == ids[0]
        assert incident["report"]["incident_id"] == ids[0]
        assert incident["evidence_citations"] == report.evidence_citations
    finally:
        reopened._get_connection().close()


@pytest.mark.asyncio
async def test_tenant_scoped_identity_and_updates(db, report):
    store = SqliteIncidentRepository(db)
    first = await store.create_ticket(report, "tenant-a")
    second = await store.create_ticket(report, "tenant-b")
    assert first != second
    assert (await store.get_by_alert(report.alert_id, "tenant-a"))["id"] == first
    assert await store.get_by_alert(report.alert_id, "tenant-c") is None
    with pytest.raises(NotFoundError):
        await store.get_ticket(first, "tenant-b")
    final = replace(report, verdict=report.verdict.model_copy(update={"summary": "Final assessment"}),
                    evidence_citations=[{"source": "final", "evidence_id": "ev-2"}])
    # Duplicate admission does not erase the existing assessment or lifecycle.
    assert await store.create_ticket(final, "tenant-a") == first
    assert (await store.get_ticket(first, "tenant-a"))["summary"] == "Initial assessment"
    with pytest.raises(NotFoundError):
        await store.update_ticket_report(first, "tenant-b", final)
    with pytest.raises(NotFoundError):
        await store.update_ticket_status(first, "tenant-b", "RESOLVED")
    await store.update_ticket_status(first, "tenant-a", "RESOLVED", resolution_category="true_positive",
                                     resolution_notes="Checked")
    updated = await store.update_ticket_report(first, "tenant-a", final)
    assert updated["id"] == first
    assert updated["summary"] == "Final assessment"
    assert updated["report"]["incident_id"] == first
    assert updated["evidence_citations"] == final.evidence_citations
    assert updated["status"] == "RESOLVED"
    assert updated["resolution_notes"] == "Checked"
    assert updated["resolution_category"] == "true_positive"
    assert updated["resolved_at"]
    assert updated["threat_intel_score"] == "Not assessed"
    assert updated["time_to_decision_sec"] is None
    restart = Database(db.db_path)
    try:
        saved = await SqliteIncidentRepository(restart).get_ticket(first, "tenant-a")
        assert saved["report"]["incident_id"] == first
        assert saved["summary"] == "Final assessment"
        assert saved["evidence_citations"] == final.evidence_citations
        assert saved["status"] == "RESOLVED"
    finally:
        restart._get_connection().close()
    reopened = await store.update_ticket_status(first, "tenant-a", "OPEN")
    assert reopened["resolved_at"] == ""
    empty = await store.update_ticket_report(first, "tenant-a", final, evidence_citations=[])
    assert empty["evidence_citations"] == []
    assert empty["report"]["evidence_citations"] == []
    with pytest.raises(ConflictError):
        await store.update_ticket_report(first, "tenant-a", replace(final, incident_id=second))
    mismatched = replace(final, evidence=replace(final.evidence, alert=final.evidence.alert.model_copy(update={"id": "other"})))
    with pytest.raises(ConflictError):
        await store.update_ticket_report(first, "tenant-a", mismatched)


@pytest.mark.asyncio
async def test_external_dispatch_marker_survives_restart_and_does_not_replace_id(db, report):
    store = SqliteIncidentRepository(db)
    incident = await store.create_ticket(report, "tenant-a")
    assert await store.claim_external_ticket(incident, "tenant-a")
    assert not await store.claim_external_ticket(incident, "tenant-a")
    await store.mark_external_ticket_unknown(incident, "tenant-a", "network timeout")
    reopened = Database(db.db_path)
    try:
        restored = SqliteIncidentRepository(reopened)
        assert not await restored.claim_external_ticket(incident, "tenant-a")
        marker = await restored.get_external_ticket(incident, "tenant-a")
        assert marker["state"] == "unknown"
        assert marker["error"] == "network timeout"
        binding = await restored.bind_external_ticket(incident, "tenant-a", "SOC-17")
        assert binding["external_id"] == "SOC-17"
        assert binding["state"] == "bound"
        assert (await restored.get_ticket(incident, "tenant-a"))["id"] == incident
        with pytest.raises(NotFoundError):
            await restored.get_external_ticket(incident, "tenant-b")
        with pytest.raises(NotFoundError):
            await restored.bind_external_ticket(incident, "tenant-b", "SOC-18")
        with pytest.raises(ConflictError):
            await restored.bind_external_ticket(incident, "tenant-a", "SOC-18")
    finally:
        reopened._get_connection().close()


@pytest.mark.asyncio
async def test_legacy_duplicate_upgrade_preserves_every_record(db, report):
    store = SqliteIncidentRepository(db)
    first = await store.create_ticket(report, "tenant-a")
    row = db.fetchone("SELECT * FROM incidents WHERE ticket_id = ?", (first,))
    second = "LEGACY-SECOND"
    third = "LEGACY-OTHER-TENANT"
    db.execute("INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)",
               ("tenant-b", "B", "2020-01-01"))
    row.update(ticket_id=second, created_at="2000-01-01", summary="Preserve legacy evidence", status="CLOSED")
    columns = ", ".join(row)
    placeholders = ", ".join("?" for _ in row)
    db.execute(f"INSERT INTO incidents ({columns}) VALUES ({placeholders})", tuple(row.values()))  # noqa: S608
    row.update(ticket_id=third, org_id="tenant-b")
    db.execute(f"INSERT INTO incidents ({columns}) VALUES ({placeholders})", tuple(row.values()))  # noqa: S608
    # Simulate the pre-canonical, pre-citation schema, including a custom column.
    db.execute("DROP TABLE incident_external_tickets")
    db.execute("DROP TABLE incident_alert_links")
    for column in ("evidence_citations_json", "raw_payload_json", "report_json"):
        db.execute(f"ALTER TABLE incidents DROP COLUMN {column}")
    db.execute("ALTER TABLE incidents ADD COLUMN legacy_note TEXT DEFAULT 'retain me'")
    before = db.fetchall("SELECT * FROM incidents ORDER BY ticket_id")
    db._get_connection().close()
    db._local.conn = None
    reopened = Database(db.db_path)
    try:
        migrated = SqliteIncidentRepository(reopened)
        assert await migrated.create_ticket(report, "tenant-a") == second
        assert await migrated.create_ticket(report, "tenant-b") == third
        assert len(reopened.fetchall("SELECT * FROM incidents")) == 3
        assert [item["id"] for item in await migrated.list_tickets("tenant-a")] == [second]
        assert (await migrated.get_ticket(first, "tenant-a"))["id"] == first
        for original in before:
            restored = reopened.fetchone("SELECT * FROM incidents WHERE ticket_id = ? AND org_id = ?",
                                         (original["ticket_id"], original["org_id"]))
            assert {key: restored[key] for key in original} == original
        assert (await migrated.get_ticket(second, "tenant-a"))["evidence_citations"] == []
        reopened._get_connection().close()
        reopened._local.conn = None
        again = Database(db.db_path)
        try:
            assert await SqliteIncidentRepository(again).create_ticket(report, "tenant-a") == second
            assert again.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 3
        finally:
            again._get_connection().close()
    finally:
        reopened._get_connection().close()


@pytest.mark.asyncio
async def test_workflow_checkpoint_keeps_latest_report_and_incident_on_reopen(db, report):
    incident = await SqliteIncidentRepository(db).create_ticket(report, "tenant-a")
    repo = SqliteWorkflowRunRepository(db)
    repo.create_run("tenant-a", "run-1", "workflow-1", report.alert_id, {},
                    report.evidence.alert, report, incident_id=incident)
    final = replace(report, evidence_citations=[{"source": "checkpoint"}], incident_id=incident)
    repo.update_run_report("tenant-a", "run-1", final, incident)
    with pytest.raises(NotFoundError):
        repo.update_run_report("tenant-b", "run-1", final, incident)
    reopened = Database(db.db_path)
    try:
        checkpoint = SqliteWorkflowRunRepository(reopened).get_run("tenant-a", "run-1")
        assert checkpoint["incident_id"] == incident
        assert checkpoint["base_report"] == json.loads(json.dumps(final.to_dict()))
    finally:
        reopened._get_connection().close()


@pytest.mark.asyncio
async def test_failed_mapping_insert_rolls_back_incident_and_allows_retry(db, report):
    db.execute("""CREATE TRIGGER fail_canonical_link BEFORE INSERT ON incident_alert_links
                  BEGIN SELECT RAISE(ABORT, 'injected mapping failure'); END""")
    store = SqliteIncidentRepository(db)
    with pytest.raises(Exception, match="injected mapping failure"):
        await store.create_ticket(report, "tenant-a")
    assert db.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 0
    assert db.fetchone("SELECT COUNT(*) AS n FROM incident_alert_links")["n"] == 0
    db.execute("DROP TRIGGER fail_canonical_link")
    incident = await store.create_ticket(report, "tenant-a", raw_payload={})
    assert (await store.get_ticket(incident, "tenant-a"))["raw_payload"] == {}


@pytest.mark.asyncio
async def test_claim_sweeper_preserves_checkpoint_and_incident(db, report):
    incident = await SqliteIncidentRepository(db).create_ticket(report, "tenant-a")
    claims = SqliteAlertClaimRepository(db)
    assert claims.claim_alert("tenant-a", report.alert_id)[0]
    claims.update_claim_status("tenant-a", report.alert_id, "WAITING", "WAITING", 0,
                               report=replace(report, incident_id=incident), incident_id=incident)
    original = claims.get_claim("tenant-a", report.alert_id)
    claims.update_claim_status("tenant-a", report.alert_id, "FAILED", "INTERRUPTED", 0)
    preserved = claims.get_claim("tenant-a", report.alert_id)
    assert preserved["report"] == original["report"]
    assert preserved["incident_id"] == incident
    assert preserved["outcome"] == "INTERRUPTED"


@pytest.mark.asyncio
async def test_metrics_aggregate_all_canonical_incidents_without_list_limit(db, report):
    store = SqliteIncidentRepository(db)
    for index in range(105):
        alert = report.evidence.alert.model_copy(update={"id": f"alert-{index}"})
        incident_report = replace(report, alert_id=alert.id, evidence=replace(report.evidence, alert=alert),
                                  verdict=report.verdict.model_copy(update={"severity": Severity.CRITICAL}))
        incident = await store.create_ticket(incident_report, "tenant-a")
        if index < 3:
            await store.update_ticket_status(incident, "tenant-a", ("RESOLVED", "CLOSED", "FALSE_POSITIVE")[index])
    assert len(await store.list_tickets("tenant-a")) == 100
    assert await store.get_incident_counts("tenant-a") == {"total": 105, "open": 102, "resolved": 3, "critical": 105}
    assert await store.get_incident_counts("other-tenant") == {"total": 0, "open": 0, "resolved": 0, "critical": 0}
