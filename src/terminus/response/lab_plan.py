"""Review-only Scenario A plans from canonical evidence; never dispatches actions."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from terminus.orchestration.models import EvidenceRecord


def build_lab_response_plan(records: list[EvidenceRecord], incident_id: str) -> dict[str, Any]:  # noqa: C901, PLR0912 -- bounded defensive parsing of recorded provider data
    """Fixed lab scope, exact evidence citations, and explicit live-execution gates."""
    if not records or any(record.incident_id != incident_id for record in records):
        raise ValueError("Evidence must belong to this incident")
    matches: dict[str, str] = {}
    citations: set[str] = set()
    organizations = {record.org_id for record in records}
    if len(organizations) != 1:
        raise ValueError("Evidence must belong to one organization")
    for record in records:
        content = record.content
        if record.source != "wazuh-indexer" or not isinstance(content, dict):
            continue
        if content.get("tool_id") != "alerts.search":
            continue
        for observation in content.get("observed", []):
            if not isinstance(observation, dict):
                continue
            alert = observation.get("alert")
            if not isinstance(alert, dict):
                continue
            agent, data, rule = (alert.get(key, {}) for key in ("agent", "data", "rule"))
            if not all(isinstance(item, dict) for item in (agent, data, rule)):
                continue
            if (agent.get("id"), agent.get("ip"), data.get("srcip")) != ("001", "10.77.0.20", "10.77.0.10"):
                continue
            if "authentication_failed" not in rule.get("groups", []) or "sshd" not in rule.get("groups", []):
                continue
            event_id = observation.get("event_id")
            timestamp = alert.get("timestamp")
            if isinstance(event_id, str) and isinstance(timestamp, str):
                datetime.fromisoformat(timestamp)
                matches[event_id] = timestamp
                citations.add(record.evidence_id)
    if len(matches) < 3:
        raise ValueError("At least three distinct SSH failure events from the fixed lab source are required")
    return {
        "kind": "lab_response_review", "incident_id": incident_id,
        "created_at": datetime.now(UTC).isoformat(),
        "execution_enabled": False, "approval_state": "not_requested",
        "recommendation": "Temporarily block Kali's lab IP on the Ubuntu target",
        "agent_id": "001", "target_ip": "10.77.0.20", "source_ip": "10.77.0.10",
        "duration_seconds": 60, "evidence_ids": sorted(citations),
        "source_event_ids": sorted(matches), "latest_observed_failure": max(matches.values()),
        "reason": "Repeated failed SSH authentication from the lab source; successful compromise is not established.",
        "impact": "All inbound traffic from Kali's lab IP to this target is denied for 60 seconds. Windows management access must remain available.",
        "prerequisites": ["Recheck fresh evidence and exact agent mapping", "Confirm Kali SSH baseline and Windows management access", "Obtain approval bound to immutable proposal and expiry", "Persist a single dispatch intent before external I/O"],
        "verification": ["Observe Kali SSH fail after dispatch", "Observe Windows management SSH still succeed", "Inspect owned nftables set and remaining timeout", "Observe Kali SSH recover after expiry"],
        "undo": "Remove only the nftables table whose ownership matches this action's intent and proposal digest.",
        "limitations": ["Review plan only: no live approval or dispatch authorization", "Historical observations do not establish a current attack", "Provider acknowledgement alone is not verification"],
    }
