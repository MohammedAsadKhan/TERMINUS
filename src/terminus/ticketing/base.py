from __future__ import annotations

from typing import Protocol

from terminus.core.ids import OrgId, TicketId
from terminus.models import InvestigationReport


class TicketStore(Protocol):
    async def create_ticket(
        self, report: InvestigationReport, org_id: OrgId
    ) -> TicketId: ...

    async def get_ticket(
        self, ticket_id: TicketId, org_id: OrgId
    ) -> dict[str, str]: ...

    async def list_tickets(
        self, org_id: OrgId
    ) -> list[dict[str, str]]: ...
