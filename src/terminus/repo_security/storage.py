"""SQLite persistence for repository scans, findings, components, and finding events."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from terminus.storage.db import Database


class SqliteRepoSecurityRepository:
    """Organization-scoped storage for repository security scanning results."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def create_scan(
        self,
        org_id: str,
        asset_id: str,
        trigger: str,
        commit_sha: str | None = None,
    ) -> dict[str, Any]:
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT INTO repo_scans (scan_id, org_id, asset_id, trigger, commit_sha, status, started_at, stats_json) "
            "VALUES (?, ?, ?, ?, ?, 'queued', ?, '{}')",
            (scan_id, str(org_id), str(asset_id), trigger, commit_sha, started_at),
        )
        row = self.get_scan(org_id, scan_id)
        if row is None:
            raise RuntimeError("Created scan could not be retrieved")
        return row

    def update_scan_status(
        self,
        org_id: str,
        scan_id: str,
        status: str,
        stats: dict[str, Any] | None = None,
        error: str | None = None,
        commit_sha: str | None = None,
    ) -> dict[str, Any] | None:
        finished_at = datetime.now(UTC).isoformat() if status in ("completed", "partial", "failed") else None
        updates = ["status = ?"]
        params: list[Any] = [status]

        if stats is not None:
            updates.append("stats_json = ?")
            params.append(json.dumps(stats))
        if error is not None:
            updates.append("error = ?")
            params.append(error)
        if finished_at is not None:
            updates.append("finished_at = ?")
            params.append(finished_at)
        if commit_sha is not None:
            updates.append("commit_sha = ?")
            params.append(commit_sha)

        params.extend([str(scan_id), str(org_id)])
        self.db.execute(
            f"UPDATE repo_scans SET {', '.join(updates)} WHERE scan_id = ? AND org_id = ?",
            tuple(params),
        )
        return self.get_scan(org_id, scan_id)

    def get_scan(self, org_id: str, scan_id: str) -> dict[str, Any] | None:
        row = self.db.fetchone(
            "SELECT scan_id, org_id, asset_id, trigger, commit_sha, status, started_at, finished_at, error, stats_json "
            "FROM repo_scans WHERE scan_id = ? AND org_id = ?",
            (str(scan_id), str(org_id)),
        )
        if row is None:
            return None
        stats = {}
        if row.get("stats_json"):
            try:
                stats = json.loads(row["stats_json"])
            except Exception:
                stats = {}
        return {**row, "stats": stats}

    def list_scans(
        self,
        org_id: str,
        asset_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = min(max(1, limit), 200)
        offset = max(0, offset)
        rows = self.db.fetchall(
            "SELECT scan_id, org_id, asset_id, trigger, commit_sha, status, started_at, finished_at, error, stats_json "
            "FROM repo_scans WHERE org_id = ? AND asset_id = ? ORDER BY started_at DESC, scan_id LIMIT ? OFFSET ?",
            (str(org_id), str(asset_id), limit, offset),
        )
        results = []
        for r in rows:
            stats = {}
            if r.get("stats_json"):
                try:
                    stats = json.loads(r["stats_json"])
                except Exception:
                    stats = {}
            results.append({**r, "stats": stats})
        return results

    def record_findings(
        self,
        org_id: str,
        asset_id: str,
        scan_id: str,
        findings: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        now = datetime.now(UTC).isoformat()
        stored: list[dict[str, Any]] = []

        with self.db.transaction() as conn:
            for item in findings:
                fingerprint = str(item["fingerprint"])
                category = str(item["category"])
                rule = str(item["rule"])
                severity = str(item["severity"])
                file_path = item.get("file")
                line = item.get("line")
                commit_sha = item.get("commit_sha")
                preview = item.get("preview")
                details = json.dumps(item.get("details", {}))

                existing = conn.execute(
                    "SELECT finding_id, status FROM repo_findings WHERE org_id = ? AND asset_id = ? AND fingerprint = ?",
                    (str(org_id), str(asset_id), fingerprint),
                ).fetchone()

                if existing:
                    finding_id = existing["finding_id"]
                    status = existing["status"]
                    # If it was resolved, re-open since it's detected again
                    new_status = "open" if status == "resolved" else status
                    conn.execute(
                        "UPDATE repo_findings SET scan_id = ?, severity = ?, file = ?, line = ?, "
                        "commit_sha = ?, preview = ?, details_json = ?, status = ?, last_seen = ? "
                        "WHERE finding_id = ?",
                        (
                            scan_id,
                            severity,
                            file_path,
                            line,
                            commit_sha,
                            preview,
                            details,
                            new_status,
                            now,
                            finding_id,
                        ),
                    )
                else:
                    finding_id = str(uuid.uuid4())
                    conn.execute(
                        "INSERT INTO repo_findings (finding_id, org_id, asset_id, scan_id, category, rule, "
                        "severity, file, line, commit_sha, fingerprint, preview, details_json, status, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)",
                        (
                            finding_id,
                            str(org_id),
                            str(asset_id),
                            scan_id,
                            category,
                            rule,
                            severity,
                            file_path,
                            line,
                            commit_sha,
                            fingerprint,
                            preview,
                            details,
                            now,
                            now,
                        ),
                    )

                stored.append(self.get_finding(org_id, finding_id) or {})
        return stored

    def get_finding(self, org_id: str, finding_id: str) -> dict[str, Any] | None:
        row = self.db.fetchone(
            "SELECT finding_id, org_id, asset_id, scan_id, category, rule, severity, file, line, "
            "commit_sha, fingerprint, preview, details_json, status, first_seen, last_seen "
            "FROM repo_findings WHERE finding_id = ? AND org_id = ?",
            (str(finding_id), str(org_id)),
        )
        if row is None:
            return None
        details = {}
        if row.get("details_json"):
            try:
                details = json.loads(row["details_json"])
            except Exception:
                details = {}
        return {**row, "details": details}

    def list_findings(
        self,
        org_id: str,
        asset_id: str | None = None,
        severity: str | None = None,
        status: str | None = None,
        category: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = min(max(1, limit), 200)
        offset = max(0, offset)

        clauses = ["org_id = ?"]
        params: list[Any] = [str(org_id)]

        if asset_id is not None:
            clauses.append("asset_id = ?")
            params.append(str(asset_id))
        if severity is not None:
            clauses.append("severity = ?")
            params.append(str(severity))
        if status is not None:
            clauses.append("status = ?")
            params.append(str(status))
        if category is not None:
            clauses.append("category = ?")
            params.append(str(category))

        where_sql = " AND ".join(clauses)
        params.extend([limit, offset])

        rows = self.db.fetchall(
            f"SELECT finding_id, org_id, asset_id, scan_id, category, rule, severity, file, line, "
            f"commit_sha, fingerprint, preview, details_json, status, first_seen, last_seen "
            f"FROM repo_findings WHERE {where_sql} ORDER BY first_seen DESC, finding_id LIMIT ? OFFSET ?",
            tuple(params),
        )
        results = []
        for r in rows:
            details = {}
            if r.get("details_json"):
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    details = {}
            results.append({**r, "details": details})
        return results

    def update_finding_status(
        self,
        org_id: str,
        finding_id: str,
        new_status: str,
        actor: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        finding = self.get_finding(org_id, finding_id)
        if finding is None:
            return None

        from_status = finding["status"]
        if from_status == new_status:
            return finding

        event_id = str(uuid.uuid4())
        now = datetime.now(UTC).isoformat()
        event_details = json.dumps(details or {})

        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE repo_findings SET status = ?, last_seen = ? WHERE finding_id = ? AND org_id = ?",
                (new_status, now, str(finding_id), str(org_id)),
            )
            conn.execute(
                "INSERT INTO repo_finding_events (event_id, finding_id, org_id, actor, from_status, to_status, timestamp, details_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event_id, str(finding_id), str(org_id), actor, from_status, new_status, now, event_details),
            )

        return self.get_finding(org_id, finding_id)

    def record_components(
        self,
        org_id: str,
        asset_id: str,
        commit_sha: str,
        components: list[dict[str, Any]],
    ) -> None:
        with self.db.transaction() as conn:
            for comp in components:
                conn.execute(
                    "INSERT OR REPLACE INTO repo_components (org_id, asset_id, commit_sha, ecosystem, name, version, source_file) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(org_id),
                        str(asset_id),
                        str(commit_sha),
                        str(comp["ecosystem"]),
                        str(comp["name"]),
                        str(comp["version"]),
                        str(comp["source_file"]),
                    ),
                )

    def list_components(
        self,
        org_id: str,
        asset_id: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = min(max(1, limit), 200)
        offset = max(0, offset)

        clauses = ["org_id = ?"]
        params: list[Any] = [str(org_id)]

        if asset_id is not None:
            clauses.append("asset_id = ?")
            params.append(str(asset_id))

        where_sql = " AND ".join(clauses)
        params.extend([limit, offset])

        return self.db.fetchall(
            f"SELECT org_id, asset_id, commit_sha, ecosystem, name, version, source_file "
            f"FROM repo_components WHERE {where_sql} ORDER BY ecosystem, name, version LIMIT ? OFFSET ?",
            tuple(params),
        )

    def sweep_stale_scans(self) -> int:
        now = datetime.now(UTC).isoformat()
        cursor = self.db.execute(
            "UPDATE repo_scans SET status = 'failed', error = 'Scan abandoned or timed out during server restart', "
            "finished_at = ? WHERE status IN ('queued', 'running')",
            (now,),
        )
        return cursor.rowcount
