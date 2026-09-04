from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport, SiemAlert
from terminus.pipeline.deployment import PipelineDeployment


class PipelineRunner:
    def __init__(self, deployment: PipelineDeployment) -> None:
        self.deployment = deployment

    async def process_alert(
        self, alert: SiemAlert, org_id: OrgId
    ) -> InvestigationReport:
        report = await self.deployment.agent.investigate(alert, org_id)

        if report.policy.should_investigate:
            await self.deployment.ticket_store.create_ticket(report, org_id)

        await self.deployment.notifier.notify(report, org_id)

        return report
