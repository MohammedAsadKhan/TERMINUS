"""Durable, local-only application gateway state for the fictional bank demo.

This controls only the demo bank routes. It does not dispatch Wazuh, firewall,
host-isolation, or production network actions.
"""

from __future__ import annotations

import ipaddress
import os
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import Request

from terminus.storage.db import Database

DEMO_ATTACK_NET = ipaddress.ip_network("203.0.113.0/24")
DEMO_NORMAL_NET = ipaddress.ip_network("198.51.100.0/24")


class BankDemoDefense:
    """Record actual demo requests and enforce source blocks at the bank API."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database.get_instance()
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS bank_demo_events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, observed_at TEXT NOT NULL, "
            "source_ip TEXT NOT NULL, campaign TEXT NOT NULL, outcome TEXT NOT NULL, "
            "detail TEXT NOT NULL, alert_id TEXT)"
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS bank_demo_events_source_time "
            "ON bank_demo_events(source_ip, observed_at)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS bank_demo_blocks ("
            "source_ip TEXT PRIMARY KEY, blocked_at TEXT NOT NULL, "
            "reason TEXT NOT NULL, alert_id TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS bank_demo_sessions ("
            "token TEXT PRIMARY KEY, source_ip TEXT NOT NULL, expires_at REAL NOT NULL)"
        )

    @staticmethod
    def source_ip(request: Request) -> str:
        """Accept a fictional source header only from a loopback demo client."""
        peer = request.client.host if request.client else "unknown"
        header = request.headers.get("X-Demo-Source-IP", "")
        if os.getenv("TERMINUS_BANK_DEMO_MODE") == "1" and peer in {"127.0.0.1", "::1", "testclient"}:
            try:
                candidate = ipaddress.ip_address(header)
            except ValueError:
                pass
            else:
                if candidate in DEMO_ATTACK_NET or candidate in DEMO_NORMAL_NET:
                    return str(candidate)
        return peer

    def is_blocked(self, source_ip: str) -> bool:
        return self.db.fetchone(
            "SELECT 1 FROM bank_demo_blocks WHERE source_ip=?", (source_ip,)
        ) is not None

    def record(
        self,
        source_ip: str,
        campaign: str,
        outcome: str,
        detail: str,
        alert_id: str | None = None,
    ) -> int:
        cursor = self.db.execute(
            "INSERT INTO bank_demo_events(observed_at,source_ip,campaign,outcome,detail,alert_id) "
            "VALUES (?,?,?,?,?,?)",
            (datetime.now(UTC).isoformat(), source_ip, campaign, outcome, detail[:240], alert_id),
        )
        return int(cursor.lastrowid)

    def failed_login_count(self, source_ip: str, *, window_seconds: int = 60) -> int:
        cutoff = datetime.fromtimestamp(time.time() - window_seconds, UTC).isoformat()
        row = self.db.fetchone(
            "SELECT COUNT(*) AS total FROM bank_demo_events "
            "WHERE source_ip=? AND outcome='failed_login' AND observed_at>=?",
            (source_ip, cutoff),
        )
        return int(row["total"]) if row else 0

    def block(self, source_ip: str, reason: str, alert_id: str) -> bool:
        """Block only fictional attack addresses; never block the presenter."""
        try:
            allowed = ipaddress.ip_address(source_ip) in DEMO_ATTACK_NET
        except ValueError:
            allowed = False
        if not allowed:
            return False
        self.db.execute(
            "INSERT OR IGNORE INTO bank_demo_blocks(source_ip,blocked_at,reason,alert_id) "
            "VALUES (?,?,?,?)",
            (source_ip, datetime.now(UTC).isoformat(), reason, alert_id),
        )
        return self.is_blocked(source_ip)

    def create_session(self, source_ip: str) -> str:
        token = uuid4().hex + uuid4().hex
        self.db.execute(
            "INSERT INTO bank_demo_sessions(token,source_ip,expires_at) VALUES (?,?,?)",
            (token, source_ip, time.time() + 900),
        )
        return token

    def valid_session(self, token: str, source_ip: str) -> bool:
        return self.db.fetchone(
            "SELECT 1 FROM bank_demo_sessions "
            "WHERE token=? AND source_ip=? AND expires_at>?",
            (token, source_ip, time.time()),
        ) is not None

    def status(self) -> dict[str, Any]:
        totals = {
            row["outcome"]: row["total"]
            for row in self.db.fetchall(
                "SELECT outcome, COUNT(*) AS total FROM bank_demo_events GROUP BY outcome"
            )
        }
        blocks = self.db.fetchall(
            "SELECT source_ip,blocked_at,reason,alert_id FROM bank_demo_blocks "
            "ORDER BY blocked_at DESC LIMIT 8"
        )
        events = self.db.fetchall(
            "SELECT observed_at,source_ip,campaign,outcome,detail,alert_id "
            "FROM bank_demo_events ORDER BY id DESC LIMIT 12"
        )
        controls = self.db.fetchall(
            "SELECT observed_at,source_ip,campaign,outcome,detail,alert_id "
            "FROM bank_demo_events WHERE outcome IN ('attack_denied','blocked') "
            "ORDER BY id DESC LIMIT 6"
        )
        started = float(os.getenv("TERMINUS_BANK_DEMO_STARTED_AT", "0"))
        duration = int(os.getenv("TERMINUS_BANK_DEMO_DURATION", "600"))
        remaining = max(0, round(started + duration - time.time())) if started else 0
        return {
            "mode": "LOCAL SYNTHETIC DEMO",
            "control": "Terminus bank application gateway",
            "duration_seconds": duration,
            "remaining_seconds": remaining,
            "totals": totals,
            "active_blocks": len(self.db.fetchall("SELECT source_ip FROM bank_demo_blocks")),
            "blocks": blocks,
            "recent_events": events,
            "recent_controls": controls,
            "external_firewall_or_wazuh_action": False,
        }
