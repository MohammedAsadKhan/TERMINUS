"""Durable, tenant-scoped seven-day relationship graph over observed alerts."""

# ruff: noqa: S608 - SQL fragments are fixed server-side clauses; values use bound parameters.

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport, SiemAlert
from terminus.storage.db import Database


def _event_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC).isoformat()
    except ValueError:
        return datetime.now(UTC).isoformat()


class GraphEventStore:
    """Store raw event evidence independently of the transient ticket queue."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or Database.get_instance()

    def record(self, alert: SiemAlert, org_id: OrgId, report: InvestigationReport, incident_id: str | None) -> None:
        self.db.execute(
            """INSERT OR IGNORE INTO graph_events
            (org_id, alert_id, incident_id, occurred_at, ingested_at, source_ip, host,
             rule_description, mitre, level, severity, policy_tier, campaign_id, raw_event)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                str(org_id), alert.id, incident_id, _event_time(alert.timestamp), datetime.now(UTC).isoformat(),
                alert.src_ip, alert.agent_name or str(alert.agent_id or "Unknown host"),
                alert.description, alert.mitre, alert.level, report.verdict.severity.value,
                report.policy.tier.value, report.campaign_id, alert.full_log,
            ),
        )

    def snapshot(self, org_id: OrgId, since: str, until: str, policy: str = "all") -> dict[str, Any]:
        where = "org_id = ? AND occurred_at >= ? AND occurred_at <= ?"
        params: list[Any] = [str(org_id), since, until]
        if policy != "all":
            where += " AND policy_tier = ?"
            params.append(policy)
        totals = self.db.fetchone(
            f"SELECT COUNT(*) AS events, SUM(CASE WHEN policy_tier != 'ignore' THEN 1 ELSE 0 END) AS investigated FROM graph_events WHERE {where}",
            tuple(params),
        ) or {"events": 0, "investigated": 0}
        rows = self.db.fetchall(
            f"""SELECT source_ip, host, COUNT(*) AS event_count,
                SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                MIN(occurred_at) AS first_seen, MAX(occurred_at) AS last_seen,
                GROUP_CONCAT(DISTINCT mitre) AS techniques
                FROM graph_events WHERE {where}
                GROUP BY source_ip, host ORDER BY event_count DESC, last_seen DESC LIMIT 120""",
            tuple(params),
        )
        daily = self.db.fetchall(
            f"SELECT substr(occurred_at, 1, 10) AS day, COUNT(*) AS event_count FROM graph_events WHERE {where} GROUP BY day ORDER BY day",
            tuple(params),
        )
        sources: dict[str, dict[str, Any]] = {}
        hosts: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        for row in rows:
            host = str(row["host"])
            count = int(row["event_count"])
            host_node = hosts.setdefault(host, {"id": f"host:{host}", "kind": "host", "label": host, "event_count": 0, "critical_count": 0})
            host_node["event_count"] += count
            host_node["critical_count"] += int(row["critical_count"] or 0)
            source = row["source_ip"]
            if source:
                source = str(source)
                source_node = sources.setdefault(source, {"id": f"source:{source}", "kind": "source", "label": source, "event_count": 0, "critical_count": 0, "local_test": source.startswith("127.") or source == "::1"})
                source_node["event_count"] += count
                source_node["critical_count"] += int(row["critical_count"] or 0)
                edges.append({
                    "id": f"edge:{source}:{host}", "source": f"source:{source}", "target": f"host:{host}",
                    "source_ip": source, "host": host, "event_count": count,
                    "critical_count": int(row["critical_count"] or 0), "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"], "techniques": (row["techniques"] or "").split(",") if row["techniques"] else [],
                    "relationship": "Observed source on host; not proof of common operator",
                })
        return {
            "from": since, "until": until, "total_events": int(totals["events"] or 0),
            "investigated_events": int(totals["investigated"] or 0),
            "nodes": list(sources.values()) + list(hosts.values()), "edges": edges,
            "daily_counts": daily,
            "hidden_relationships": max(0, int(self.db.fetchone(f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM graph_events WHERE {where} GROUP BY source_ip, host)", tuple(params))["n"]) - len(rows)),
            "note": "Links reflect structured source IP and host fields. Shared infrastructure does not establish attacker identity.",
        }

    def network(self, org_id: OrgId, since: str, until: str, policy: str = "all", limit: int = 1500) -> dict[str, Any]:
        where = "org_id = ? AND occurred_at >= ? AND occurred_at <= ?"
        params: list[Any] = [str(org_id), since, until]
        if policy != "all":
            where += " AND policy_tier = ?"
            params.append(policy)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM graph_events WHERE {where}", tuple(params))["n"]
        rows = self.db.fetchall(
            f"""SELECT alert_id, occurred_at, source_ip, host, mitre, severity,
                policy_tier, rule_description FROM graph_events WHERE {where}
                ORDER BY occurred_at DESC LIMIT ?""",
            (*params, limit),
        )
        return {"total_events": total, "shown_events": len(rows), "truncated": total > len(rows), "events": rows}

    def evidence(self, org_id: OrgId, since: str, until: str, *, source_ip: str | None = None, host: str | None = None, mitre: str | None = None, alert_id: str | None = None, policy: str = "all", limit: int = 100, offset: int = 0) -> dict[str, Any]:
        where = "org_id = ? AND occurred_at >= ? AND occurred_at <= ?"
        params: list[Any] = [str(org_id), since, until]
        if source_ip is not None:
            where += " AND source_ip = ?"
            params.append(source_ip)
        if host is not None:
            where += " AND host = ?"
            params.append(host)
        if mitre is not None:
            where += " AND mitre = ?"
            params.append(mitre)
        if alert_id is not None:
            where += " AND alert_id = ?"
            params.append(alert_id)
        if policy != "all":
            where += " AND policy_tier = ?"
            params.append(policy)
        total = self.db.fetchone(f"SELECT COUNT(*) AS n FROM graph_events WHERE {where}", tuple(params))["n"]
        rows = self.db.fetchall(
            f"""SELECT alert_id, incident_id, occurred_at, ingested_at, source_ip, host,
                rule_description, mitre, level, severity, policy_tier, campaign_id, raw_event
                FROM graph_events WHERE {where} ORDER BY occurred_at DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        )
        return {"total": total, "events": rows, "limit": limit, "offset": offset}
