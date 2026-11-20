# File name: base.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Define the interface for creating tickets from investigation reports.

from __future__ import annotations

from typing import Any, Protocol

from terminus.core.ids import OrgId, TicketId
from terminus.models import InvestigationReport


class TicketStore(Protocol):
    """Contract for tenant-scoped ticket storage used by investigations and reports."""
    async def create_ticket(
        self, report: InvestigationReport, org_id: OrgId
    ) -> TicketId: ...

    async def get_ticket(
        self, ticket_id: TicketId, org_id: OrgId
    ) -> dict[str, Any]: ...

    async def list_tickets(
        self, org_id: OrgId
    ) -> list[dict[str, Any]]: ...
