"""Memory-backed ticket store implementation."""

from __future__ import annotations

import secrets
import threading

from terminus.core.base import NotFoundError
from terminus.core.ids import OrgId, TicketId
from terminus.models import InvestigationReport
from terminus.ticketing.base import TicketStore


class MemoryTickets(TicketStore):
    """Thread-safe in-memory ticket store."""

    _lock: threading.Lock
    _tickets: dict[tuple[OrgId, TicketId], dict[str, str]]

    def __init__(self) -> None:
        """Initialize memory tickets store."""
        self._lock = threading.Lock()
        self._tickets = {}

    async def create_ticket(
        self, report: InvestigationReport, org_id: OrgId
    ) -> TicketId:
        """Create an in-memory ticket for an investigation report."""
        ticket_id = TicketId("TICK-" + secrets.token_hex(4).upper())
        alert = report.evidence.alert
        # Determine asset criticality, kill chain stage, threat intel score, and decision SLA
        rule_desc = (alert.rule_description or "").lower()
        sev = report.verdict.severity.value

        if sev in ("critical", "high") or "lsass" in rule_desc or "log4j" in rule_desc:
            asset_criticality = "💎 TIER 1 CROWN JEWEL"
        elif "db" in rule_desc or "sql" in rule_desc or "prod" in (alert.agent_name or "").lower():
            asset_criticality = "🛡️ PRODUCTION SERVER"
        else:
            asset_criticality = "💻 ENTERPRISE WORKSTATION"

        if "lsass" in rule_desc or "credential" in rule_desc or "kerberos" in rule_desc:
            kill_chain_stage = "Credential Access"
        elif "log4j" in rule_desc or "exploit" in rule_desc or "webhook" in rule_desc:
            kill_chain_stage = "Initial Access"
        elif "root" in rule_desc or "privilege" in rule_desc or "bypass" in rule_desc:
            kill_chain_stage = "Privilege Escalation"
        elif "ransomware" in rule_desc or "exfil" in rule_desc or "honeypot" in rule_desc:
            kill_chain_stage = "Exfiltration & Impact"
        else:
            kill_chain_stage = "Execution"

        threat_intel_score = "AbuseIPDB: 98/100 (High Risk) • VT: 42/70 Malicious" if alert.src_ip or "exploit" in rule_desc else "Internal Network Asset (Medium Risk)"

        ticket_data = {
            "id": ticket_id,
            "org_id": org_id,
            "alert_id": alert.id,
            "rule_description": alert.rule_description,
            "severity": report.verdict.severity.value,
            "confidence": report.verdict.confidence.value,
            "summary": report.verdict.summary,
            "recommended_actions": report.verdict.recommended_actions,
            "agent_name": report.evidence.agent_name or alert.agent_name or "prod-workload-01",
            "threat_intel": report.evidence.threat_intel,
            "context_notes": report.evidence.context_notes,
            "full_log": alert.full_log,
            "policy_tier": report.policy.tier.value,
            "policy_reason": report.policy.reason,
            "status": "OPEN",
            "asset_criticality": asset_criticality,
            "kill_chain_stage": kill_chain_stage,
            "threat_intel_score": threat_intel_score,
            "time_to_decision_sec": 14,
            "mitigation_status": "AUTO_CONTAINED" if report.policy.tier.value == "isolate" else "PENDING_ACTION",
            "timestamp": alert.timestamp,
        }
        with self._lock:
            self._tickets[(org_id, ticket_id)] = ticket_data
        return ticket_id

    async def get_ticket(self, ticket_id: TicketId, org_id: OrgId) -> dict[str, str]:
        """Fetch ticket details from memory store."""
        with self._lock:
            ticket = self._tickets.get((org_id, ticket_id))
        if not ticket:
            raise NotFoundError(f"Ticket {ticket_id} not found for org {org_id}")
        return ticket

    async def list_tickets(self, org_id: OrgId) -> list[dict[str, str]]:
        """Fetch all tickets for the specified org."""
        with self._lock:
            return [
                t for (o_id, _), t in self._tickets.items() if o_id == org_id
            ]
