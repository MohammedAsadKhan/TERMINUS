# File name: test_campaign_persistence.py
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Verify tenant-scoped campaign continuity, replay safety and time windows.

"""Exercise durable campaign assignment across independent SQLite connections."""

from __future__ import annotations

from pathlib import Path

import pytest

from terminus.core.ids import RuleId
from terminus.correlation.stitcher import CampaignStitcher
from terminus.models import SiemAlert
from terminus.storage.db import Database


def _alert(alert_id: str, level: int = 5) -> SiemAlert:
    return SiemAlert(
        id=alert_id,
        rule_id=RuleId(5710),
        level=level,
        description=f"Lab event {alert_id}",
        agent_name="terminus-target-a",
        src_ip="10.77.0.10",
        mitre="T1110",
    )


def test_campaign_survives_restart_and_duplicate_does_not_inflate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr("terminus.correlation.stitcher.time.time", lambda: now[0])
    path = str(tmp_path / "campaigns.db")
    first_db = Database(path)
    first = CampaignStitcher(db=first_db).process(_alert("alert-1"), "org-one")
    first_db.close()

    now[0] += 30
    second_db = Database(path)
    stitcher = CampaignStitcher(db=second_db)
    second = stitcher.process(_alert("alert-2", level=10), "org-one")
    replay = stitcher.process(_alert("alert-1"), "org-one")

    assert second.campaign_id == first.campaign_id == replay.campaign_id
    assert second.alert_count == replay.alert_count == 2
    assert second.highest_level == 10
    assert "Lab event alert-2" in second.to_summary()
    second_db.close()


def test_campaign_isolated_by_tenant_and_expires_by_window(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr("terminus.correlation.stitcher.time.time", lambda: now[0])
    db = Database(str(tmp_path / "campaigns.db"))
    stitcher = CampaignStitcher(window_seconds=60, db=db)
    first = stitcher.process(_alert("same-id"), "org-one")
    other = stitcher.process(_alert("same-id"), "org-two")
    assert first.campaign_id != other.campaign_id
    assert other.alert_count == 1

    now[0] += 61
    later = stitcher.process(_alert("later"), "org-one")
    assert later.campaign_id != first.campaign_id
    assert later.alert_count == 1
    db.close()


def test_campaign_store_does_not_duplicate_raw_alert_data(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "campaigns.db"))
    alert = _alert("sensitive").model_copy(
        update={"full_log": "private raw log marker", "location": "private path marker"}
    )
    campaign = CampaignStitcher(db=db).process(alert, "org-one")
    row = db.fetchone(
        "SELECT payload_json FROM campaign_alerts WHERE org_id=? AND alert_id=?",
        ("org-one", "sensitive"),
    )
    assert row is not None
    assert "private raw log marker" not in row["payload_json"]
    assert "private path marker" not in row["payload_json"]
    assert campaign.alert_count == 1
    db.close()
