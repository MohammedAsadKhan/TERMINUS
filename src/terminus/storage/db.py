"""Persistent database engine and table definitions for TERMINUS 2.0.

Provides thread-safe async SQLite persistence with connection management,
automatic schema creation, and database snapshots.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any


class Database:
    """Thread-safe SQLite database manager for Terminus."""

    _instance: Database | None = None
    _lock = threading.Lock()

    def __init__(self, db_path: str = "terminus.db") -> None:
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    @classmethod
    def get_instance(cls, db_path: str = "terminus.db") -> Database:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
            return cls._instance

    @classmethod
    def reset_instance(cls, db_path: str = ":memory:") -> Database:
        with cls._lock:
            cls._instance = cls(db_path)
            return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0,
                isolation_level=None,  # autocommit mode
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            self._local.conn = conn
        return self._local.conn

    def execute(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> sqlite3.Cursor:
        conn = self._get_connection()
        return conn.execute(sql, params)

    def executemany(self, sql: str, params_seq: list[tuple[Any, ...] | dict[str, Any]]) -> sqlite3.Cursor:
        conn = self._get_connection()
        return conn.executemany(sql, params_seq)

    def fetchone(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> dict[str, Any] | None:
        cur = self.execute(sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self, sql: str, params: tuple[Any, ...] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        cur = self.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

    def _init_db(self) -> None:
        """Create all required tables, apply column migrations, and build indexes."""
        table_statements = [
            """
            CREATE TABLE IF NOT EXISTS organizations (
                org_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                license_ref TEXT,
                settings_json TEXT DEFAULT '{}'
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS memberships (
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                PRIMARY KEY (org_id, user_id),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS incidents (
                ticket_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                rule_id TEXT,
                rule_description TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                summary TEXT NOT NULL,
                recommended_actions TEXT NOT NULL,
                agent_name TEXT,
                threat_intel TEXT,
                context_notes TEXT,
                full_log TEXT,
                policy_tier TEXT NOT NULL,
                policy_reason TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                asset_criticality TEXT DEFAULT 'MEDIUM',
                kill_chain_stage TEXT,
                threat_intel_score TEXT,
                time_to_decision_sec REAL,
                mitigation_status TEXT DEFAULT 'NOT_EXECUTED',
                evidence_citations_json TEXT DEFAULT '[]',
                raw_payload_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                resolved_at TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS soc_agents (
                agent_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                role_description TEXT NOT NULL,
                master_prompt TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                incidents_processed INTEGER NOT NULL DEFAULT 0,
                avg_sla_ms REAL NOT NULL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                PRIMARY KEY (org_id, agent_id),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                agent_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 100,
                version INTEGER NOT NULL DEFAULT 1,
                nodes_json TEXT NOT NULL DEFAULT '[]',
                edges_json TEXT NOT NULL DEFAULT '[]',
                created_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (org_id, workflow_id),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS alert_claims (
                org_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                outcome TEXT,
                side_effects INTEGER NOT NULL DEFAULT 0,
                report_json TEXT,
                incident_id TEXT,
                claimed_at TEXT NOT NULL,
                completed_at TEXT,
                PRIMARY KEY (org_id, alert_id),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                run_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL,
                outcome TEXT,
                side_effects INTEGER NOT NULL DEFAULT 0,
                unknown_outcome INTEGER NOT NULL DEFAULT 0,
                definition_snapshot TEXT NOT NULL,
                alert_json TEXT NOT NULL,
                base_report_json TEXT NOT NULL,
                edge_states_json TEXT NOT NULL DEFAULT '{}',
                incident_id TEXT,
                errors_json TEXT NOT NULL DEFAULT '[]',
                heartbeat_at TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                UNIQUE (workflow_id, alert_id, attempt),
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS node_runs (
                node_run_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                node_type TEXT NOT NULL,
                status TEXT NOT NULL,
                inputs_json TEXT NOT NULL DEFAULT '{}',
                outputs_json TEXT NOT NULL DEFAULT '{}',
                error_message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (run_id) REFERENCES workflow_runs(run_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS workflow_approvals (
                approval_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                workflow_id TEXT NOT NULL,
                org_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                required_role TEXT NOT NULL DEFAULT 'admin',
                prompt_message TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                resolved_by TEXT,
                resolved_at TEXT,
                FOREIGN KEY (run_id) REFERENCES workflow_runs(run_id) ON DELETE CASCADE,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS containment_allowlist (
                entry_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS detection_tuning_rules (
                rule_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                incident_id TEXT,
                name TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                target_platform TEXT NOT NULL,
                rule_content TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PROPOSED',
                backtest_results_json TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                indicator TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                reputation_score REAL NOT NULL,
                malicious INTEGER NOT NULL,
                provider_details_json TEXT NOT NULL,
                cached_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS action_logs (
                action_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                actor_type TEXT NOT NULL,
                actor_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT DEFAULT '{}',
                incident_id TEXT,
                alert_id TEXT,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS graph_events (
                org_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                incident_id TEXT,
                occurred_at TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                source_ip TEXT,
                host TEXT NOT NULL,
                rule_description TEXT NOT NULL,
                mitre TEXT,
                level INTEGER NOT NULL,
                severity TEXT NOT NULL,
                policy_tier TEXT NOT NULL,
                campaign_id TEXT,
                raw_event TEXT NOT NULL,
                PRIMARY KEY (org_id, alert_id)
            );
            """,
        ]

        conn = self._get_connection()
        for stmt in table_statements:
            conn.executescript(stmt)

        # Apply column migrations for preexisting tables
        for table, col, col_def in [
            ("workflows", "priority", "INTEGER NOT NULL DEFAULT 100"),
            ("workflows", "version", "INTEGER NOT NULL DEFAULT 1"),
            ("workflows", "created_by", "TEXT"),
            ("workflow_runs", "outcome", "TEXT"),
            ("workflow_runs", "definition_snapshot", "TEXT NOT NULL DEFAULT '{}'"),
            ("workflow_runs", "heartbeat_at", "TEXT NOT NULL DEFAULT ''"),
            ("workflow_runs", "attempt", "INTEGER NOT NULL DEFAULT 1"),
            ("workflow_runs", "side_effects", "INTEGER NOT NULL DEFAULT 0"),
            ("workflow_runs", "unknown_outcome", "INTEGER NOT NULL DEFAULT 0"),
        ]:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def};")
            except sqlite3.OperationalError:
                pass

        # Create indexes after columns are guaranteed to exist
        index_statements = [
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_soc_agents_org_agent ON soc_agents(org_id, agent_id);",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_workflows_org_wf ON workflows(org_id, workflow_id);",
            "CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents(org_id, status);",
            "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);",
            "CREATE INDEX IF NOT EXISTS idx_soc_agents_org ON soc_agents(org_id);",
            "CREATE INDEX IF NOT EXISTS idx_workflows_org ON workflows(org_id, enabled, priority);",
            "CREATE INDEX IF NOT EXISTS idx_wfruns_org ON workflow_runs(org_id, started_at DESC);",
            "CREATE INDEX IF NOT EXISTS idx_wfruns_status ON workflow_runs(status, heartbeat_at);",
            "CREATE INDEX IF NOT EXISTS idx_noderuns_run ON node_runs(run_id);",
            "CREATE INDEX IF NOT EXISTS idx_noderuns_org ON node_runs(org_id);",
            "CREATE INDEX IF NOT EXISTS idx_approvals_org_status ON workflow_approvals(org_id, status, expires_at);",
            "CREATE INDEX IF NOT EXISTS idx_allowlist_org ON containment_allowlist(org_id);",
            "CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_action_logs_org_time ON action_logs(org_id, timestamp DESC);",
            "CREATE INDEX IF NOT EXISTS idx_graph_events_org_time ON graph_events(org_id, occurred_at DESC);",
            "CREATE INDEX IF NOT EXISTS idx_graph_events_org_pair ON graph_events(org_id, source_ip, host, occurred_at DESC);",
        ]
        for stmt in index_statements:
            conn.execute(stmt)


def create_connection(db_path: str | Path = "terminus.db") -> sqlite3.Connection:
    """Create and configure a standalone SQLite connection with WAL & FKs enabled."""
    conn = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        timeout=30.0,
        isolation_level=None,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db(db_path: str | Path = "terminus.db") -> None:
    """Initialize a database at the given path."""
    Database.reset_instance(str(db_path))
