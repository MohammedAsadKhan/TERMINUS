# File name: stitcher.py
# Author: Team LARP
# Revision date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Tenant-scoped temporal campaign stitching with optional durable state.

"""Correlate tenant alerts by host, source and time window.

Operational mode stores the assignment and only the fields needed to summarize
recent alerts. Raw logs and extra Wazuh fields remain in their original stores.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from _thread import LockType
from dataclasses import dataclass, field
from typing import cast

from terminus.models import SiemAlert
from terminus.storage.db import Database


@dataclass
class StitchedCampaign:
    """A group of related alerts for one organization, host and source IP inside the
    correlation window.
    """
    campaign_id: str
    org_id: str
    primary_host: str
    source_ip: str | None
    first_seen: float
    last_seen: float
    alerts: list[SiemAlert] = field(default_factory=list)
    tactics_seen: set[str] = field(default_factory=set)
    highest_level: int = 1
    total_alert_count: int | None = None

    def add_alert(self, alert: SiemAlert) -> None:
        """Append an alert, refresh the last-seen time, and track the highest level and
        MITRE tags seen.
        """
        self.alerts.append(alert)
        self.last_seen = time.time()
        self.highest_level = max(self.highest_level, alert.level)
        if alert.mitre:
            self.tactics_seen.add(alert.mitre)

    @property
    def alert_count(self) -> int:
        """Return the stored total when one is known, else the number of alerts held in
        memory.
        """
        return (
            self.total_alert_count
            if self.total_alert_count is not None
            else len(self.alerts)
        )

    def to_summary(self) -> str:
        """Build a one-paragraph description with the tactics and the five most recent
        alerts.
        """
        descriptions = [f"[{a.timestamp}] {a.description}" for a in self.alerts[-5:]]
        return (
            f"Stitched Campaign across {self.alert_count} events on host '{self.primary_host}'. "
            f"Tactics: {', '.join(sorted(self.tactics_seen)) or 'None'}. "
            f"Recent alerts: {'; '.join(descriptions)}"
        )


class CampaignStitcher:
    """Sliding-window attack campaign correlator."""

    def __init__(
        self, window_seconds: float = 900.0, db: Database | None = None
    ) -> None:  # 15 minute window
        """Set the correlation window and optional database; without a database
        campaigns live only in process memory.
        """
        self.window_seconds: float = window_seconds
        self.db: Database | None = db
        self._campaigns: dict[str, StitchedCampaign] = {}
        self._lock: LockType = threading.Lock()

    def process(self, alert: SiemAlert, org_id: str) -> StitchedCampaign:
        """Assign alert to an existing active campaign or instantiate a new campaign."""
        if self.db is not None:
            return self._process_durable(alert, org_id)
        host = alert.agent_name or (
            str(alert.agent_id) if alert.agent_id else "unknown-host"
        )
        src = alert.src_ip or "no-ip"
        key = f"{org_id}:{host}:{src}"
        now = time.time()

        with self._lock:
            # Clean up expired campaigns
            expired = [
                k
                for k, c in self._campaigns.items()
                if now - c.last_seen > self.window_seconds
            ]
            for k in expired:
                del self._campaigns[k]

            existing = self._campaigns.get(key)
            if existing is None:
                campaign_id = f"camp-{secrets.token_hex(4)}"
                existing = StitchedCampaign(
                    campaign_id=campaign_id,
                    org_id=org_id,
                    primary_host=host,
                    source_ip=alert.src_ip,
                    first_seen=now,
                    last_seen=now,
                )
                self._campaigns[key] = existing

            existing.add_alert(alert)
            return existing

    def _process_durable(self, alert: SiemAlert, org_id: str) -> StitchedCampaign:
        """Atomically assign one tenant alert, including after a process restart.

        The alert ID is unique per tenant so a replay cannot inflate the count.
        BEGIN IMMEDIATE serializes a competing worker's read/insert decision.
        """
        if self.db is None:
            raise RuntimeError("Durable stitcher needs a database")
        host = alert.agent_name or (
            str(alert.agent_id) if alert.agent_id else "unknown-host"
        )
        source_key = alert.src_ip or "no-ip"
        now = time.time()
        with self.db.transaction():
            prior = self.db.fetchone(
                "SELECT campaign_id FROM campaign_alerts WHERE org_id=? AND alert_id=?",
                (org_id, alert.id),
            )
            if prior is not None:
                campaign_id = cast(str, prior["campaign_id"])
            else:
                active = self.db.fetchone(
                    """SELECT campaign_id FROM campaigns
                    WHERE org_id=? AND host=? AND source_ip_key=? AND last_seen>=?
                    ORDER BY last_seen DESC LIMIT 1""",
                    (org_id, host, source_key, now - self.window_seconds),
                )
                if active is None:
                    campaign_id = f"camp-{secrets.token_hex(8)}"
                    _ = self.db.execute(
                        "INSERT INTO campaigns VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            campaign_id,
                            org_id,
                            host,
                            source_key,
                            alert.src_ip,
                            now,
                            now,
                            0,
                            1,
                            "[]",
                        ),
                    )
                else:
                    campaign_id = cast(str, active["campaign_id"])
                _ = self.db.execute(
                    "INSERT INTO campaign_alerts VALUES(?,?,?,?,?)",
                    (
                        org_id,
                        alert.id,
                        campaign_id,
                        now,
                        alert.model_dump_json(
                            include={
                                "id",
                                "rule_id",
                                "level",
                                "description",
                                "timestamp",
                            }
                        ),
                    ),
                )
                current = self.db.fetchone(
                    """SELECT tactics_json, highest_level FROM campaigns
                    WHERE org_id=? AND campaign_id=?""",
                    (org_id, campaign_id),
                )
                if current is None:
                    raise RuntimeError("Campaign disappeared during assignment")
                tactics = _tactics(cast(object, current["tactics_json"]))
                if alert.mitre:
                    tactics.add(alert.mitre)
                _ = self.db.execute(
                    """UPDATE campaigns SET last_seen=?, alert_count=alert_count+1,
                    highest_level=?, tactics_json=?
                    WHERE org_id=? AND campaign_id=?""",
                    (
                        now,
                        max(cast(int, current["highest_level"]), alert.level),
                        json.dumps(sorted(tactics)),
                        org_id,
                        campaign_id,
                    ),
                )
            campaign = self.db.fetchone(
                "SELECT * FROM campaigns WHERE org_id=? AND campaign_id=?",
                (org_id, campaign_id),
            )
            if campaign is None:
                raise RuntimeError("Stored campaign is unavailable")
            recent = self.db.fetchall(
                """SELECT payload_json FROM campaign_alerts
                WHERE org_id=? AND campaign_id=?
                ORDER BY seen_at DESC, alert_id DESC LIMIT 5""",
                (org_id, campaign_id),
            )
        return StitchedCampaign(
            campaign_id=campaign_id,
            org_id=org_id,
            primary_host=cast(str, campaign["host"]),
            source_ip=cast(str | None, campaign["source_ip"]),
            first_seen=cast(float, campaign["first_seen"]),
            last_seen=cast(float, campaign["last_seen"]),
            alerts=[
                SiemAlert.model_validate_json(cast(str, row["payload_json"]))
                for row in reversed(recent)
            ],
            tactics_seen=_tactics(cast(object, campaign["tactics_json"])),
            highest_level=cast(int, campaign["highest_level"]),
            total_alert_count=cast(int, campaign["alert_count"]),
        )


def _tactics(value: object) -> set[str]:
    """Reject malformed stored metadata rather than silently changing correlation."""
    if not isinstance(value, str):
        raise ValueError("Invalid campaign tactics")
    raw = cast(object, json.loads(value))
    if not isinstance(raw, list):
        raise ValueError("Invalid campaign tactics")
    items = cast(list[object], raw)
    if any(not isinstance(item, str) for item in items):
        raise ValueError("Invalid campaign tactics")
    return {item for item in items if isinstance(item, str)}
