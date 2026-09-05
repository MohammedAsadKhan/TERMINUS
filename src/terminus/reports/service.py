"""Daily Incident Operations and Executive Summary Report service."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from terminus.models import DailyIncidentReport, DailyReportMetrics, ReportType


async def generate_daily_report(
    org_id: str,
    report_type: ReportType,
    ticket_store: Any,
) -> DailyIncidentReport:
    """Generate a new daily incident operations report based on tenant ticket logs.

    Args:
        org_id: Target tenant organization ID.
        report_type: 'quick' (start of day to now) or 'daily_24h' (past 24 hours).
        ticket_store: Active tenant ticket store to aggregate incident telemetry from.

    Returns:
        Structured DailyIncidentReport domain object.
    """
    now = datetime.now(UTC)
    if report_type == ReportType.QUICK:
        period_start_dt = datetime(now.year, now.month, now.day, 0, 0, 0, tzinfo=UTC)
        title_tag = "Quick Report"
    else:
        period_start_dt = now - timedelta(hours=24)
        title_tag = "24-Hour Operations Summary"

    period_start_str = period_start_dt.isoformat()
    period_end_str = now.isoformat()

    tickets = await ticket_store.list_tickets(org_id)

    def in_window(ticket: dict) -> bool:
        timestamp = ticket.get("created_at") or ticket.get("timestamp")
        if not timestamp:
            return False
        try:
            received = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if received.tzinfo is None:
                return False
            return period_start_dt <= received < now
        except ValueError:
            return False

    tickets = [ticket for ticket in tickets if in_window(ticket)]
    total = len(tickets)
    critical = 0
    high = 0
    medium = 0
    low = 0
    contained = 0
    resolved = 0
    host_counts: dict[str, int] = {}

    for t in tickets:
        sev = str(t.get("severity", "")).lower()
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        else:
            low += 1

        status_str = str(t.get("status", "")).upper()
        mitigation = str(t.get("mitigation_status", "")).upper()
        if "CONTAINED" in status_str or "CONTAINED" in mitigation:
            contained += 1
        if status_str == "RESOLVED":
            resolved += 1

        agent_name = t.get("agent_name") or "Unknown host"
        host_counts[agent_name] = host_counts.get(agent_name, 0) + 1

    top_hosts = [
        {"host": host, "incident_count": cnt}
        for host, cnt in sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    metrics = DailyReportMetrics(
        total_incidents=total,
        critical_incidents=critical,
        high_incidents=high,
        medium_incidents=medium,
        low_incidents=low,
        contained_incidents=contained,
        resolved_incidents=resolved,
        avg_mttd_sec=None,
        avg_mttr_sec=None,
    )

    report_id = f"rep-{secrets.token_hex(4)}"
    title = f"Daily Incident Report — {now.strftime('%b %d, %Y')} ({title_tag})"

    time_range_fmt = f"{period_start_dt.strftime('%H:%M')} to {now.strftime('%H:%M UTC')}"
    if total == 0:
        narrative = (
            f"During the report window ({time_range_fmt}), "
            "the TERMINUS AI SOC platform monitored tenant workloads with zero active security policy violations. "
            "No incident records were created in this period; endpoint health is not inferred from incident counts."
        )
        recommendations = [
            "Maintain active Wazuh SIEM telemetry ingestion feeds and policy engines.",
            "Run scheduled threat hunting loops across critical production hosts.",
            "Verify backup posture for crown jewel database servers.",
        ]
    else:
        narrative = (
            f"Between {time_range_fmt}, the TERMINUS platform processed {total} security incident log(s) "
            f"({critical} Critical, {high} High, {medium} Medium, {low} Low). "
            f"{resolved} incident(s) were marked resolved as of report generation. "
            f"Primary impacted workloads: {', '.join([h['host'] for h in top_hosts])}."
        )
        recommendations = [
            "Review firewall IP block lists for perimeter attacker addresses.",
            "Isolate non-essential service accounts flagged during privilege escalation events.",
            "Ensure host memory protection modules are active across top targeted servers.",
        ]

    return DailyIncidentReport(
        id=report_id,
        org_id=org_id,
        title=title,
        report_type=report_type,
        created_at=now.isoformat(),
        period_start=period_start_str,
        period_end=period_end_str,
        metrics=metrics,
        executive_summary=narrative,
        top_impacted_hosts=top_hosts,
        recommended_actions=recommendations,
    )
