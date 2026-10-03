"""Organization-scoped inventory asset persistence."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from terminus.storage.db import Database


class SqliteAssetRepository:
    """Store plain inventory metadata without connecting to the asset itself."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db

    @property
    def db(self) -> Database:
        return self._db if self._db is not None else Database.get_instance()

    def list_for_org(self, org_id: str, kind: str | None = None) -> list[dict[str, str | None]]:
        if kind is None:
            rows = self.db.fetchall(
                "SELECT asset_id, org_id, kind, name, locator, notes, source, created_at "
                "FROM assets WHERE org_id = ? ORDER BY created_at DESC, asset_id",
                (str(org_id),),
            )
        else:
            rows = self.db.fetchall(
                "SELECT asset_id, org_id, kind, name, locator, notes, source, created_at "
                "FROM assets WHERE org_id = ? AND kind = ? ORDER BY created_at DESC, asset_id",
                (str(org_id), kind),
            )
        return rows

    def create(
        self,
        org_id: str,
        kind: str,
        name: str,
        locator: str | None,
        notes: str | None,
    ) -> dict[str, str | None]:
        asset_id = str(uuid.uuid4())
        created_at = datetime.now(UTC).isoformat()
        self.db.execute(
            "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) "
            "VALUES (?, ?, ?, '', '{}')",
            (str(org_id), f"Organization {org_id}", created_at),
        )
        self.db.execute(
            "INSERT INTO assets (asset_id, org_id, kind, name, locator, notes, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'manual', ?)",
            (asset_id, str(org_id), kind, name, locator, notes, created_at),
        )
        row = self.db.fetchone(
            "SELECT asset_id, org_id, kind, name, locator, notes, source, created_at "
            "FROM assets WHERE asset_id = ? AND org_id = ?",
            (asset_id, str(org_id)),
        )
        if row is None:  # pragma: no cover - INSERT and SELECT share the same connection
            raise RuntimeError("Inserted asset could not be loaded")
        return row

    def delete(self, org_id: str, asset_id: str) -> bool:
        cursor = self.db.execute(
            "DELETE FROM assets WHERE asset_id = ? AND org_id = ?",
            (asset_id, str(org_id)),
        )
        return cursor.rowcount > 0
