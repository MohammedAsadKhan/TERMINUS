"""Pipeline Runner orchestrator for TERMINUS.

Implements end-to-end alert processing with:
- Idempotent alert claims (D5)
- Priority-ordered first-match workflow selection (D2)
- Pre-engine autonomous base investigation (D3)
- Gap-filling for notifications and ticketing (D4)
- Live graph event recording and SSE event broadcasting (D21)
"""

from __future__ import annotations

import logging
from dataclasses import replace

from terminus.core.ids import OrgId
from terminus.correlation.stitcher import CampaignStitcher
from terminus.investigation.graph import GraphEventStore
from terminus.models import InvestigationReport, SiemAlert
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.triggers import trigger_matches
from terminus.pipeline.workflow_engine import WorkflowEngine, WorkflowExecutionContext
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAlertClaimRepository,
    SqliteWorkflowRepository,
)

logger = logging.getLogger("terminus.pipeline.runner")


class PipelineRunner:
    """End-to-end incident investigation and response pipeline runner."""

    def __init__(
        self,
        deployment: PipelineDeployment,
        workflow_engine: WorkflowEngine | None = None,
        stitcher: CampaignStitcher | None = None,
        claim_repo: SqliteAlertClaimRepository | None = None,
        workflow_repo: SqliteWorkflowRepository | None = None,
        db: Database | None = None,
    ) -> None:
        self.deployment = deployment
        self.db = db
        self.workflow_engine = workflow_engine or WorkflowEngine(db=db)
        self.stitcher = stitcher or CampaignStitcher()
        self.graph_store = GraphEventStore()
        self.claim_repo = claim_repo or SqliteAlertClaimRepository(db=db)
        self.workflow_repo = workflow_repo or SqliteWorkflowRepository(db=db)

    async def process_alert(
        self,
        alert: SiemAlert,
        org_id: OrgId | str,
    ) -> InvestigationReport:
        org_str = str(org_id)
        alert_id = str(alert.id)

        # 1. Idempotent Alert Claim (D5)
        claimed, existing_claim = self.claim_repo.claim_alert(org_str, alert_id)
        if not claimed:
            # Check if we can atomically re-claim after safe failure (D5)
            reclaimed, claim_record = self.claim_repo.reclaim_alert_if_failed_before_side_effects(org_str, alert_id)
            if not reclaimed:
                # Duplicate alert or active run - return stored report if available
                if claim_record and claim_record.get("report"):
                    try:
                        return InvestigationReport.from_dict(claim_record["report"])
                    except Exception:
                        pass
                if existing_claim and existing_claim.get("report"):
                    try:
                        return InvestigationReport.from_dict(existing_claim["report"])
                    except Exception:
                        pass
                logger.info(f"Alert {alert_id} for org {org_str} is already claimed/processed. Skipping.")
                # If no report dict is available (e.g. still running), perform a fallback or return existing
                if existing_claim and existing_claim.get("report_json"):
                    import json
                    try:
                        return InvestigationReport.from_dict(json.loads(existing_claim["report_json"]))
                    except Exception:
                        pass

        # 2. Temporal Campaign Stitching
        campaign = self.stitcher.process(alert, org_str)

        # 3. Pre-Engine Autonomous Base Investigation (D3)
        base_report = await self.deployment.agent.investigate(alert, OrgId(org_str))
        report = replace(base_report, campaign_id=campaign.campaign_id, campaign_alert_count=campaign.alert_count)

        # 4. First-Match Workflow Evaluation (D2)
        matching_workflow = None
        try:
            enabled_workflows = self.workflow_repo.list_enabled(org_str)
            for wf in enabled_workflows:
                # Find trigger node (D1, D2)
                trigger_node = next((n for n in wf.nodes if n.type == "trigger_wazuh"), None)
                trigger_cfg = trigger_node.config if trigger_node else {}
                if trigger_matches(trigger_cfg, alert):
                    matching_workflow = wf
                    break
        except Exception as e:
            logger.warning(f"Error querying workflows for org {org_str}: {e}")

        # 5. Execute Matched Workflow (if any) (D2, D3, D6)
        wf_ctx: WorkflowExecutionContext | None = None
        if matching_workflow:
            try:
                wf_ctx = await self.workflow_engine.execute_workflow(
                    workflow=matching_workflow,
                    alert=alert,
                    org_id=org_str,
                    base_report=report,
                    deployment=self.deployment,
                    dry_run=False,
                )
                if wf_ctx.report:
                    report = wf_ctx.report
            except Exception as e:
                logger.error(f"Unexpected workflow execution error: {e}")

        # 6. Gap-Filling for Incident Ticketing and Notifications (D4)
        incident_id: str | None = None
        ticket_already_created = bool(wf_ctx and wf_ctx.ticket_created)

        if report.policy.should_investigate and not ticket_already_created:
            try:
                created_id = await self.deployment.ticket_store.create_ticket(report, OrgId(org_str))
                incident_id = str(created_id)
            except Exception as e:
                logger.error(f"Error in gap-filling ticket creation: {e}")
        elif ticket_already_created:
            incident_id = str(getattr(wf_ctx, "incident_id", None) or f"WF-TICK-{alert_id}")

        # Record in 7-day investigation graph store
        try:
            self.graph_store.record(alert, OrgId(org_str), report, incident_id)
        except Exception as e:
            logger.warning(f"Error recording graph event: {e}")

        # Notification gap-filling (D4)
        notified_channels = wf_ctx.notified if wf_ctx else set()
        if not ("slack" in notified_channels or "default" in notified_channels):
            try:
                await self.deployment.notifier.notify(report, OrgId(org_str))
            except Exception as e:
                logger.error(f"Error in gap-filling notification: {e}")

        # 7. Update Claim Status and Outcome (D5, D7)
        if wf_ctx:
            final_status = wf_ctx.status
            final_outcome = wf_ctx.outcome
            side_effects = 1 if wf_ctx.side_effects_executed else 0
        else:
            final_status = "COMPLETED"
            final_outcome = "HANDLED"
            side_effects = 0

        self.claim_repo.update_claim_status(
            org_id=org_str,
            alert_id=alert_id,
            status=final_status,
            outcome=final_outcome,
            side_effects=side_effects,
            report=report,
            incident_id=incident_id,
        )

        # 8. Real-Time SSE Event Broadcasting (D21)
        try:
            from terminus.server.streaming import broadcast_to_org
            broadcast_to_org(
                org_str,
                "alert_processed",
                {
                    "alert_id": alert_id,
                    "org_id": org_str,
                    "severity": str(report.verdict.severity.value if hasattr(report.verdict.severity, "value") else report.verdict.severity),
                    "tier": str(report.policy.tier.value if hasattr(report.policy.tier, "value") else report.policy.tier),
                    "summary": report.verdict.summary,
                    "status": final_status,
                    "outcome": final_outcome,
                },
            )
        except Exception as e:
            logger.debug(f"SSE broadcast non-fatal skip: {e}")

        return report
