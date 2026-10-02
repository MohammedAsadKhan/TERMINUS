"""Pipeline Runner orchestrator for TERMINUS 2.0."""

from __future__ import annotations

import logging
from dataclasses import replace

from terminus.core.ids import OrgId
from terminus.correlation.stitcher import CampaignStitcher
from terminus.investigation.graph import GraphEventStore
from terminus.models import InvestigationReport, SiemAlert
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.workflow_engine import WorkflowEngine

logger = logging.getLogger("terminus.pipeline.runner")


class PipelineRunner:
    """End-to-end incident investigation and response pipeline runner."""

    def __init__(
        self,
        deployment: PipelineDeployment,
        workflow_engine: WorkflowEngine | None = None,
        stitcher: CampaignStitcher | None = None,
    ) -> None:
        self.deployment = deployment
        self.workflow_engine = workflow_engine or WorkflowEngine()
        self.stitcher = stitcher or CampaignStitcher()
        self.graph_store = GraphEventStore()

    async def process_alert(
        self, alert: SiemAlert, org_id: OrgId
    ) -> InvestigationReport:
        # 1. Temporal Campaign Stitching
        campaign = self.stitcher.process(alert, str(org_id))

        # 2. Autonomous Investigation
        report = await self.deployment.agent.investigate(alert, org_id)
        report = replace(report, campaign_id=campaign.campaign_id, campaign_alert_count=campaign.alert_count)

        # 3. Create Persistent Ticket (if triaged or escalated)
        incident_id = None
        if report.policy.should_investigate:
            incident_id = str(await self.deployment.ticket_store.create_ticket(report, org_id))

        # Preserve every source alert, including policy-filtered events, for the
        # seven-day investigation graph. A duplicate alert ID is idempotent.
        self.graph_store.record(alert, org_id, report, incident_id)

        # 4. Multi-Channel Notification Fan-Out
        await self.deployment.notifier.notify(report, org_id)

        # 5. Execute Enabled Visual DAG Workflows
        try:
            from terminus.storage.db import Database
            from terminus.storage.repositories import SqliteWorkflowRepository
            repo = SqliteWorkflowRepository(Database.get_instance())
            workflows = repo.list_for_org(org_id)
            for wf in workflows:
                if wf.enabled:
                    await self.workflow_engine.execute_workflow(wf, alert, org_id, report)
        except Exception as e:
            logger.debug(f"Workflow execution non-fatal skip: {e}")

        # 6. Real-Time SSE Event Broadcasting
        try:
            from terminus.server.streaming import broadcaster
            await broadcaster.broadcast("alert_processed", {
                "alert_id": str(alert.id),
                "org_id": str(org_id),
                "severity": str(report.verdict.severity.value if hasattr(report.verdict.severity, "value") else report.verdict.severity),
                "tier": str(report.policy.tier.value if hasattr(report.policy.tier, "value") else report.policy.tier),
                "summary": report.verdict.summary,
            })
        except Exception as e:
            logger.debug(f"SSE broadcast non-fatal skip: {e}")

        return report
