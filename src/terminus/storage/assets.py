"""Organization-scoped inventory asset persistence."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from terminus.storage.db import Database


class SqliteAssetRepository:
    """Store plain inventory metadata without connecting to the asset itself."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def get(self, org_id: str, asset_id: str) -> dict[str, Any] | None:
        return self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at "
            "FROM assets WHERE asset_id = ? AND org_id = ?",
            (str(asset_id), str(org_id)),
        )

    def find_for_target(self, org_id: str, target: str) -> dict[str, Any] | None:
        cleaned = (target or "").strip()
        if not cleaned:
            return None
        # 1. Match agent_id
        row = self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at "
            "FROM assets WHERE org_id = ? AND agent_id = ? ORDER BY created_at DESC, asset_id LIMIT 1",
            (str(org_id), cleaned),
        )
        if row is not None:
            return row
        # 2. Match case-insensitive hostname
        row = self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at "
            "FROM assets WHERE org_id = ? AND lower(hostname) = lower(?) ORDER BY created_at DESC, asset_id LIMIT 1",
            (str(org_id), cleaned),
        )
        if row is not None:
            return row
        # 3. Match exact IP / locator
        row = self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at "
            "FROM assets WHERE org_id = ? AND locator = ? ORDER BY created_at DESC, asset_id LIMIT 1",
            (str(org_id), cleaned),
        )
        if row is not None:
            return row
        # 4. Match case-insensitive name
        row = self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at "
            "FROM assets WHERE org_id = ? AND lower(name) = lower(?) ORDER BY created_at DESC, asset_id LIMIT 1",
            (str(org_id), cleaned),
        )
        return row

    def list_for_org(
        self,
        org_id: str,
        kind: str | None = None,
        q: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = min(max(1, limit), 200)
        offset = max(0, offset)

        clauses = ["org_id = ?"]
        params: list[Any] = [str(org_id)]

        if kind is not None:
            clauses.append("kind = ?")
            params.append(str(kind))

        if q is not None and q.strip():
            query_str = f"%{q.strip().lower()}%"
            clauses.append(
                "(lower(name) LIKE ? OR lower(COALESCE(locator, '')) LIKE ? OR lower(COALESCE(hostname, '')) LIKE ?)"
            )
            params.extend([query_str, query_str, query_str])

        where_sql = " AND ".join(clauses)
        params.extend([limit, offset])

        return self.db.fetchall(
            f"SELECT asset_id, org_id, kind, name, locator, notes, source, "
            f"agent_id, hostname, criticality, owner, environment, exposure, created_at "
            f"FROM assets WHERE {where_sql} ORDER BY created_at DESC, asset_id LIMIT ? OFFSET ?",
            tuple(params),
        )

    def create(
        self,
        org_id: str,
        kind: str,
        name: str,
        locator: str | None,
        notes: str | None,
        agent_id: str | None = None,
        hostname: str | None = None,
        criticality: str | None = None,
        owner: str | None = None,
        environment: str | None = None,
        exposure: str | None = None,
        source: str = "manual",
    ) -> dict[str, Any]:
        asset_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) "
            "VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", created_at),
        )
        self.db.execute(
            "INSERT INTO assets (asset_id, org_id, kind, name, locator, notes, source, "
            "agent_id, hostname, criticality, owner, environment, exposure, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                asset_id,
                str(org_id),
                kind,
                name,
                locator,
                notes,
                source,
                agent_id,
                hostname,
                criticality,
                owner,
                environment,
                exposure,
                created_at,
            ),
        )
        row = self.get(org_id, asset_id)
        if row is None:  # pragma: no cover
            raise RuntimeError("Inserted asset could not be loaded")
        return row

    def update(
        self,
        org_id: str,
        asset_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        allowed_fields = {
            "name",
            "locator",
            "notes",
            "agent_id",
            "hostname",
            "criticality",
            "owner",
            "environment",
            "exposure",
        }
        filtered = {k: v for k, v in updates.items() if k in allowed_fields}
        if not filtered:
            return self.get(org_id, asset_id)

        set_clauses = [f"{k} = ?" for k in filtered]
        params = list(filtered.values())
        params.extend([str(asset_id), str(org_id)])

        cursor = self.db.execute(
            f"UPDATE assets SET {', '.join(set_clauses)} WHERE asset_id = ? AND org_id = ?",
            tuple(params),
        )
        if cursor.rowcount == 0:
            return None
        return self.get(org_id, asset_id)

    def delete(self, org_id: str, asset_id: str) -> bool:
        cursor = self.db.execute(
            "DELETE FROM assets WHERE asset_id = ? AND org_id = ?",
            (asset_id, str(org_id)),
        )
        return cursor.rowcount > 0
