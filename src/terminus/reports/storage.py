# File name: storage.py
# Author: Team LARP
# Revision date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Persist tenant-scoped generated reports across API restarts.

"""SQLite report history. Generation and reading always use the tenant key."""

from __future__ import annotations

from typing import cast

from terminus.models import DailyIncidentReport
from terminus.storage.db import Database


class SqliteReportStore:
    """Keep generated report snapshots durable and isolated by organization."""

    def __init__(self, db: Database) -> None:
        """Use the given database for report persistence."""
        self.db: Database = db

    def save(self, report: DailyIncidentReport) -> None:
        """Insert a generated report snapshot keyed by its organization and report ID."""
        with self.db.transaction():
            _ = self.db.execute(
                "INSERT INTO daily_reports(org_id, report_id, created_at, payload_json) VALUES(?,?,?,?)",
                (
                    report.org_id,
                    report.id,
                    report.created_at,
                    report.model_dump_json(),
                ),
            )

    def list_for_org(self, org_id: str) -> list[DailyIncidentReport]:
        """Return the organization's stored reports, newest first; other tenants'
        reports are never selected.
        """
        rows = self.db.fetchall(
            "SELECT payload_json FROM daily_reports WHERE org_id=? ORDER BY created_at DESC, report_id DESC",
            (org_id,),
        )
        reports: list[DailyIncidentReport] = []
        for row in rows:
            payload = cast(object, row["payload_json"])
            if not isinstance(payload, str):
                raise ValueError("Invalid stored report")
            reports.append(DailyIncidentReport.model_validate_json(payload))
        return reports

    def get(self, org_id: str, report_id: str) -> DailyIncidentReport | None:
        """Return one report only if it belongs to the organization, else None."""
        row = self.db.fetchone(
            "SELECT payload_json FROM daily_reports WHERE org_id=? AND report_id=?",
            (org_id, report_id),
        )
        if row is None:
            return None
        payload = cast(object, row["payload_json"])
        if not isinstance(payload, str):
            raise ValueError("Invalid stored report")
        return DailyIncidentReport.model_validate_json(payload)
