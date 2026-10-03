"""Background sweeper task for TERMINUS (D24).

Runs on server startup and every 60 seconds to:
1. Detect stale RUNNING workflows (heartbeat_at > 5 min old) and transition them to INTERRUPTED.
2. Detect expired PENDING approvals and resolve them as EXPIRED ('system:expired'), resuming the run.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAlertClaimRepository,
    SqliteApprovalRepository,
    SqliteWorkflowRunRepository,
)

logger = logging.getLogger("terminus.pipeline.sweeper")


async def run_sweeper_cycle(
    run_repo: SqliteWorkflowRunRepository,
    approval_repo: SqliteApprovalRepository,
    workflow_engine: WorkflowEngine,
    claim_repo: SqliteAlertClaimRepository | None = None,
    deployment: PipelineDeployment | None = None,
    now_iso: str = "",
    max_heartbeat_age_seconds: int = 300,
) -> dict[str, int]:
    """Executes one sweeper evaluation cycle (D24)."""
    now_str = now_iso or datetime.now(UTC).isoformat()
    interrupted_runs_count = 0
    expired_approvals_count = 0

    # 1. Sweep stale RUNNING workflow runs
    try:
        stale_runs = run_repo.get_stale_running_runs(max_heartbeat_age_seconds=max_heartbeat_age_seconds)
        for run in stale_runs:
            org_id = run["org_id"]
            run_id = run["run_id"]
            side_effects = bool(run.get("side_effects_executed", False))

            # Update run to INTERRUPTED
            run_repo.update_run(
                org_id=org_id,
                run_id=run_id,
                status="INTERRUPTED",
                outcome="INTERRUPTED",
                side_effects=side_effects,
                errors=run.get("errors", []) + ["Execution timed out / heartbeat stale"],
                completed_at=now_str,
            )
            interrupted_runs_count += 1

            # Also update alert claim if present
            if claim_repo and run.get("alert_id"):
                claim_repo.update_claim_status(
                    org_id=org_id,
                    alert_id=run["alert_id"],
                    status="INTERRUPTED",
                    outcome="INTERRUPTED",
                    side_effects=1 if side_effects else 0,
                    report=None,
                    completed_at=now_str,
                )

            # Surface via SSE if side effects were executed
            if side_effects:
                try:
                    from terminus.server.streaming import broadcast_to_org
                    broadcast_to_org(
                        org_id,
                        "workflow_interrupted_with_side_effects",
                        {
                            "run_id": run_id,
                            "org_id": org_id,
                            "workflow_id": run.get("workflow_id"),
                            "side_effects": True,
                            "message": "Workflow run was interrupted after side effects were executed.",
                        },
                    )
                except Exception as e:
                    logger.debug(f"Failed to broadcast interrupted run SSE: {e}")

    except Exception as e:
        logger.error(f"Error sweeping stale runs: {e}")

    # 2. Sweep expired PENDING approvals
    try:
        expired_approvals = approval_repo.get_expired_pending_approvals(now_iso=now_str)
        for apprv in expired_approvals:
            org_id = apprv["org_id"]
            apprv_id = apprv["approval_id"]
            run_id = apprv["run_id"]

            # Resolve approval as EXPIRED
            resolved = approval_repo.resolve_approval(
                org_id=org_id,
                approval_id=apprv_id,
                status="EXPIRED",
                resolved_by="system:expired",
                resolved_at=now_str,
            )

            if resolved:
                expired_approvals_count += 1
                try:
                    # Resume workflow run with EXPIRED outcome (D14, D24)
                    await workflow_engine.resume_run(
                        run_id=run_id,
                        org_id=org_id,
                        approval_id=apprv_id,
                        action="EXPIRED",
                        actor="system:expired",
                        deployment=deployment,
                    )
                except Exception as e:
                    logger.error(f"Error resuming run {run_id} on expired approval {apprv_id}: {e}")

    except Exception as e:
        logger.error(f"Error sweeping expired approvals: {e}")

    return {
        "interrupted_runs": interrupted_runs_count,
        "expired_approvals": expired_approvals_count,
    }


async def sweeper_background_task(
    db: Database | None = None,
    deployment: PipelineDeployment | None = None,
    interval_seconds: int = 60,
) -> None:
    """Continuous background loop executing every 60 seconds (D24)."""
    database = db or Database.get_instance()
    run_repo = SqliteWorkflowRunRepository(database)
    approval_repo = SqliteApprovalRepository(database)
    claim_repo = SqliteAlertClaimRepository(database)
    workflow_engine = WorkflowEngine(db=database)

    # Initial sweep at startup
    await run_sweeper_cycle(
        run_repo=run_repo,
        approval_repo=approval_repo,
        workflow_engine=workflow_engine,
        claim_repo=claim_repo,
        deployment=deployment,
    )

    while True:
        try:
            await asyncio.sleep(interval_seconds)
            await run_sweeper_cycle(
                run_repo=run_repo,
                approval_repo=approval_repo,
                workflow_engine=workflow_engine,
                claim_repo=claim_repo,
                deployment=deployment,
            )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[Sweeper] Error during sweep cycle: {e}")
