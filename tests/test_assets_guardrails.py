"""Tests for asset registry, tiering, guardrails, and ticket criticality mappings."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from terminus.containment.guardrails import (
    AssetCriticalityTier,
    BlastRadiusAssessment,
    BlastRadiusGuardrails,
    ContainmentGuardrail,
)
from terminus.core.ids import OrgId
from terminus.models import SiemAlert
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database, _ensure_column
from terminus.ticketing.memory import MemoryTickets


@pytest.fixture
def asset_db(tmp_path: Path) -> Database:
    db_path = str(tmp_path / "test_assets.db")
    return Database.reset_instance(db_path)


def test_idempotent_migration_preserves_rows(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)
    row1 = repo.create(
        "org-test",
        "device",
        "Server 1",
        "192.168.1.50",
        "Initial notes",
        agent_id="001",
        hostname="srv01.corp",
        criticality="tier0",
        owner="infrastructure@example.com",
        environment="production",
        exposure="internal",
    )
    assert row1["criticality"] == "tier0"

    # Run _init_db again to simulate multiple runs
    asset_db._init_db()

    # Verify column exists and row is preserved
    row_after = repo.get("org-test", row1["asset_id"])
    assert row_after is not None
    assert row_after["name"] == "Server 1"
    assert row_after["criticality"] == "tier0"
    assert row_after["agent_id"] == "001"
    assert row_after["hostname"] == "srv01.corp"


def test_find_for_target_priority_and_tenant_isolation(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)
    # Register assets in org-1
    repo.create(
        "org-1", "device", "Domain Controller", "10.0.0.5", None,
        agent_id="agent-dc", hostname="dc01.internal", criticality="tier0",
    )
    repo.create(
        "org-1", "device", "App Server", "10.0.0.20", None,
        agent_id="agent-app", hostname="app-srv.internal", criticality="tier2",
    )
    # Register same hostname in org-2 with different tier
    repo.create(
        "org-2", "device", "Org2 DC", "10.1.0.5", None,
        agent_id="agent-dc-2", hostname="dc01.internal", criticality="tier3",
    )

    # 1. Match by agent_id
    found_agent = repo.find_for_target("org-1", "agent-dc")
    assert found_agent is not None
    assert found_agent["name"] == "Domain Controller"

    # 2. Match by hostname case-insensitive
    found_host = repo.find_for_target("org-1", "DC01.INTERNAL")
    assert found_host is not None
    assert found_host["criticality"] == "tier0"

    # 3. Match by IP
    found_ip = repo.find_for_target("org-1", "10.0.0.20")
    assert found_ip is not None
    assert found_ip["name"] == "App Server"

    # 4. Multi-tenancy: org-2 returns org-2 asset
    found_org2 = repo.find_for_target("org-2", "dc01.internal")
    assert found_org2 is not None
    assert found_org2["name"] == "Org2 DC"
    assert found_org2["criticality"] == "tier3"

    # 5. Non-existent returns None
    assert repo.find_for_target("org-1", "nonexistent-target") is None


def test_guardrails_registered_tier0_blocks_even_with_force_override(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)
    # Register custom payroll host with non-matching keyword as Tier 0
    repo.create(
        "org-sec", "device", "Payroll System", "10.5.0.100", None,
        hostname="payroll-srv", criticality="tier0", owner="payroll-team",
    )

    # Assess target with asset_repo without override
    res = ContainmentGuardrail.assess_target(
        target="payroll-srv",
        org_id="org-sec",
        asset_repo=repo,
        force_override=False,
    )
    assert res.allowed is False
    assert res.asset_tier == AssetCriticalityTier.TIER_0
    assert "Tier-0" in (res.reason or "")
    assert "payroll-team" in (res.reason or "")

    # Force override MUST NOT bypass registered Tier 0
    res_override = ContainmentGuardrail.assess_target(
        target="payroll-srv",
        org_id="org-sec",
        asset_repo=repo,
        force_override=True,
    )
    assert res_override.allowed is False
    assert res_override.asset_tier == AssetCriticalityTier.TIER_0


def test_guardrails_unregistered_hostname_keyword_fallback(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)

    # dc01 is not registered in registry; keyword fallback blocks it
    res_kw = ContainmentGuardrail.assess_target(
        target="dc01.unregistered.local",
        org_id="org-sec",
        asset_repo=repo,
        force_override=False,
    )
    assert res_kw.allowed is False
    assert res_kw.asset_tier == AssetCriticalityTier.TIER_0
    assert "critical asset infrastructure keyword" in (res_kw.reason or "")

    # Force override CAN bypass keyword fallback
    res_kw_override = ContainmentGuardrail.assess_target(
        target="dc01.unregistered.local",
        org_id="org-sec",
        asset_repo=repo,
        force_override=True,
    )
    assert res_kw_override.allowed is True
    assert res_kw_override.asset_tier == AssetCriticalityTier.TIER_1


def test_guardrails_ordinary_unregistered_host_allowed(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)

    res = ContainmentGuardrail.assess_target(
        target="workstation-99.corp",
        org_id="org-sec",
        asset_repo=repo,
        force_override=False,
    )
    assert res.allowed is True
    assert res.asset_tier == AssetCriticalityTier.TIER_3
    assert res.reason is None


def test_guardrails_fail_closed_on_repository_exception() -> None:
    class FailingRepo:
        def find_for_target(self, org_id: str, target: str) -> None:
            raise RuntimeError("Database connection corrupted")

    res = ContainmentGuardrail.assess_target(
        target="some-target",
        org_id="org-sec",
        asset_repo=FailingRepo(),
        force_override=False,
    )
    assert res.allowed is False
    assert "failing closed for safety" in (res.reason or "")


@pytest.mark.asyncio
async def test_ticket_criticality_filled_from_registry(asset_db: Database) -> None:
    repo = SqliteAssetRepository(asset_db)
    repo.create(
        "org-ticket-test", "device", "Core Ledger", "192.168.10.10", None,
        agent_id="srv-ledger-01", hostname="ledger.corp", criticality="tier0", owner="fintech-sec",
    )

    from terminus.models import SiemAlert, Evidence, Verdict, InvestigationReport, PolicyResult, Tier, Severity, Confidence
    from terminus.core.ids import RuleId, AgentId

    alert = SiemAlert(
        id="alert-1234",
        rule_id=RuleId(1001),
        level=5,
        description="Suspicious SSH access",
        agent_id=AgentId("srv-ledger-01"),
        agent_name="Core Ledger",
        src_ip="198.51.100.5",
    )
    report = InvestigationReport(
        alert_id="alert-1234",
        verdict=Verdict(
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            summary="Test incident",
            recommended_actions=["Review logs"],
        ),
        evidence=Evidence(alert=alert, agent_name="Core Ledger", threat_intel="", context_notes=""),
        policy=PolicyResult(alert_id="alert-1234", tier=Tier.ESCALATE, should_investigate=True, reason="High severity"),
    )

    store = MemoryTickets()
    ticket_id = await store.create_ticket(report, OrgId("org-ticket-test"))
    ticket = await store.get_ticket(ticket_id, OrgId("org-ticket-test"))

    assert ticket["asset_criticality"] == "tier0"
    assert ticket["asset_owner"] == "fintech-sec"
