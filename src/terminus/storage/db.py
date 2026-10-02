"""Persistent database engine and table definitions for TERMINUS 2.0.

Provides thread-safe async SQLite persistence with connection management,
automatic schema creation, and database snapshots.
"""

from __future__ import annotations

import sqlite3
import threading
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
        """Create all required tables and indexes."""
        schema_statements = [
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
            CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents(org_id, status);
            CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at DESC);
            """,
            """
            CREATE TABLE IF NOT EXISTS soc_agents (
                agent_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                role_description TEXT NOT NULL,
                master_prompt TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                incidents_processed INTEGER DEFAULT 0,
                avg_sla_ms REAL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (org_id) REFERENCES organizations(org_id) ON DELETE CASCADE
            );
            """,
            """
            CREATE TABLE IF NOT EXISTS workflows (
                workflow_id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                name TEXT NOT NULL,
                agent_id TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                nodes_json TEXT NOT NULL DEFAULT '[]',
                edges_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
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
            CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, timestamp DESC);
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
            CREATE INDEX IF NOT EXISTS idx_graph_events_org_time ON graph_events(org_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_graph_events_org_pair ON graph_events(org_id, source_ip, host, occurred_at DESC);
            """,
        ]

        conn = self._get_connection()
        for stmt in schema_statements:
            conn.executescript(stmt)
