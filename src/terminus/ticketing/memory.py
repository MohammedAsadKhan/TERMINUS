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
        ticket_data = {
            "id": ticket_id,
            "org_id": org_id,
            "alert_id": alert.id,
            "severity": report.verdict.severity.value,
            "summary": report.verdict.summary,
            "status": "OPEN",
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
