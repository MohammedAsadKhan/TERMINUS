from __future__ import annotations

from dataclasses import dataclass

from terminus.agent.investigator import InvestigationAgent
from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier
from terminus.policies.engine import PolicyEngine
from terminus.ticketing.base import TicketStore


@dataclass(frozen=True)
class PipelineDeployment:
    policy_engine: PolicyEngine
    agent: InvestigationAgent
    notifier: Notifier
    ticket_store: TicketStore
    external_ticket_store: TicketStore | None = None

    async def export_ticket(
        self, incident_id: str, report: InvestigationReport, org_id: OrgId
    ) -> str | None:
        """Export once; uncertain external writes require reconciliation before retry."""
        if self.external_ticket_store is None:
            return None
        claim = getattr(self.ticket_store, "claim_external_ticket", None)
        if claim is None or not await claim(incident_id, org_id):
            return None
        try:
            external_id = await self.external_ticket_store.create_ticket(report, org_id)
            await self.ticket_store.bind_external_ticket(
                incident_id, org_id, str(external_id)
            )
            return str(external_id)
        except Exception:
            await self.ticket_store.mark_external_ticket_unknown(
                incident_id,
                org_id,
                "External ticket export failed; reconcile before retry",
            )
            raise
