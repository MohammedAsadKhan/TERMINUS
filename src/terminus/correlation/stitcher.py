"""Temporal Attack Campaign Stitching Engine for TERMINUS.

Correlates sequential alerts across time windows into unified attack campaigns,
eliminating ticket duplication and enabling end-to-end kill-chain analysis.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from terminus.models import SiemAlert


@dataclass
class StitchedCampaign:
    campaign_id: str
    org_id: str
    primary_host: str
    source_ip: str | None
    first_seen: float
    last_seen: float
    alerts: list[SiemAlert] = field(default_factory=list)
    tactics_seen: set[str] = field(default_factory=set)
    highest_level: int = 1

    def add_alert(self, alert: SiemAlert) -> None:
        self.alerts.append(alert)
        self.last_seen = time.time()
        self.highest_level = max(self.highest_level, alert.level)
        if alert.mitre:
            self.tactics_seen.add(alert.mitre)

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    def to_summary(self) -> str:
        descriptions = [f"[{a.timestamp}] {a.description}" for a in self.alerts[-5:]]
        return (
            f"Stitched Campaign across {self.alert_count} events on host '{self.primary_host}'. "
            f"Tactics: {', '.join(sorted(self.tactics_seen)) or 'None'}. "
            f"Recent alerts: {'; '.join(descriptions)}"
        )


class CampaignStitcher:
    """Sliding-window attack campaign correlator."""

    def __init__(self, window_seconds: float = 900.0) -> None:  # 15 minute window
        self.window_seconds = window_seconds
        self._campaigns: dict[str, StitchedCampaign] = {}
        self._lock = threading.Lock()

    def process(self, alert: SiemAlert, org_id: str) -> StitchedCampaign:
        """Assign alert to an existing active campaign or instantiate a new campaign."""
        host = alert.agent_name or (str(alert.agent_id) if alert.agent_id else "unknown-host")
        src = alert.src_ip or "no-ip"
        key = f"{org_id}:{host}:{src}"
        now = time.time()

        with self._lock:
            # Clean up expired campaigns
            expired = [k for k, c in self._campaigns.items() if now - c.last_seen > self.window_seconds]
            for k in expired:
                del self._campaigns[k]

            existing = self._campaigns.get(key)
            if existing is None:
                import secrets
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
