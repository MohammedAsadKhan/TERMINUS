from pathlib import Path
import sqlite3

from terminus.storage.db import Database


def _primary_key_columns(db: Database, table: str) -> list[str]:
    rows = db.fetchall(f'PRAGMA table_info("{table}")')
    return [row["name"] for row in sorted(rows, key=lambda row: row["pk"]) if row["pk"]]


def test_legacy_global_agent_and_workflow_keys_are_migrated_idempotently(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.db"
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE organizations (org_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)"
    )
    legacy.execute(
        "INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)",
        ("org-a", "A", "2026-01-01"),
    )
    legacy.execute(
        "INSERT INTO organizations (org_id, name, created_at) VALUES (?, ?, ?)",
        ("org-b", "B", "2026-01-01"),
    )
    legacy.execute(
        """CREATE TABLE soc_agents (
            agent_id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            role_description TEXT NOT NULL,
            master_prompt TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            incidents_processed INTEGER DEFAULT 0,
            avg_sla_ms REAL DEFAULT 0.0,
            created_at TEXT NOT NULL,
            legacy_note TEXT DEFAULT 'preserve me',
            FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
        )"""
    )
    legacy.execute(
        """CREATE TABLE workflows (
            workflow_id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            name TEXT NOT NULL,
            agent_id TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            nodes_json TEXT NOT NULL DEFAULT '[]',
            edges_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 100,
            version INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
        )"""
    )
    legacy.execute(
        """INSERT INTO soc_agents
           (agent_id, org_id, name, role_description, master_prompt, created_at)
           VALUES ('agent-shared', 'org-a', 'Triage', 'triage role', 'prompt-a', '2026-01-02')"""
    )
    legacy.execute(
        """INSERT INTO workflows
           (workflow_id, org_id, name, created_at, updated_at)
           VALUES ('workflow-shared', 'org-a', 'Default', '2026-01-02', '2026-01-02')"""
    )

    legacy.commit()
    legacy.close()

    # Reinitialize using the supported startup path; this creates newer tables,
    # applies the legacy column migrations, and upgrades both tenant keys.
    db = Database(str(path))

    assert _primary_key_columns(db, "soc_agents") == ["org_id", "agent_id"]
    assert _primary_key_columns(db, "workflows") == ["org_id", "workflow_id"]
    agent = db.fetchone("SELECT * FROM soc_agents WHERE org_id = 'org-a'")
    workflow = db.fetchone("SELECT * FROM workflows WHERE org_id = 'org-a'")
    assert agent is not None
    assert agent["name"] == "Triage"
    assert agent["legacy_note"] == "preserve me"
    assert workflow is not None
    assert workflow["name"] == "Default"
    assert workflow["priority"] == 100

    # Tenant-scoped IDs that collided under the old single-tenant schema now
    # coexist, and a second startup leaves the migrated rows intact.
    db.execute(
        """INSERT INTO soc_agents
           (agent_id, org_id, name, role_description, master_prompt, created_at)
           VALUES ('agent-shared', 'org-b', 'Triage B', 'triage role', 'prompt-b', '2026-01-03')"""
    )
    db.execute(
        """INSERT INTO workflows
           (workflow_id, org_id, name, created_at, updated_at)
           VALUES ('workflow-shared', 'org-b', 'Default B', '2026-01-03', '2026-01-03')"""
    )
    db = Database(str(path))
    assert (
        db.fetchone(
            "SELECT COUNT(*) AS n FROM soc_agents WHERE agent_id = 'agent-shared'"
        )["n"]
        == 2
    )
    assert (
        db.fetchone(
            "SELECT COUNT(*) AS n FROM workflows WHERE workflow_id = 'workflow-shared'"
        )["n"]
        == 2
    )
