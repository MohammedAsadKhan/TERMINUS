"""Asynchronous background execution and orchestration for repository scans."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from terminus.repo_security.commit_rules import scan_suspicious_patterns
from terminus.repo_security.deps_scan import query_osv_vulnerabilities, scan_repository_dependencies
from terminus.repo_security.sandbox import clone_repository
from terminus.repo_security.secrets_scan import scan_repository_secrets
from terminus.repo_security.storage import SqliteRepoSecurityRepository
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database

logger = logging.getLogger(__name__)

_SCAN_SEMAPHORE = asyncio.Semaphore(2)


async def execute_scan(org_id: str, asset_id: str, scan_id: str) -> dict[str, Any]:
    """Execute end-to-end repository scan under bounded semaphore concurrency."""
    async with _SCAN_SEMAPHORE:
        db = Database.get_instance()
        asset_repo = SqliteAssetRepository(db)
        scan_repo = SqliteRepoSecurityRepository(db)

        asset = asset_repo.get(org_id, asset_id)
        if not asset or asset.get("kind") != "repository":
            scan_repo.update_scan_status(
                org_id, scan_id, "failed", error="Asset not found or not a repository"
            )
            return {"status": "failed", "error": "Asset not found or not a repository"}

        locator = asset.get("locator")
        if not locator:
            scan_repo.update_scan_status(
                org_id, scan_id, "failed", error="Repository locator URL is missing"
            )
            return {"status": "failed", "error": "Repository locator URL is missing"}

        scan_repo.update_scan_status(org_id, scan_id, "running")

        try:
            # Run blocking git operations and file scans in worker thread
            def _run_scans() -> tuple[str, list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
                with clone_repository(locator) as (root, head_sha):
                    secrets = scan_repository_secrets(root, head_sha)
                    comps, dep_findings = asyncio.run(scan_repository_dependencies(root))
                    suspicious = scan_suspicious_patterns(root, head_sha)
                    return head_sha, secrets, comps, dep_findings + suspicious

            head_sha, secrets, components, other_findings = await asyncio.to_thread(_run_scans)

            all_findings = secrets + other_findings

            # Store components
            scan_repo.record_components(org_id, asset_id, head_sha, components)

            # Store findings
            stored_findings = scan_repo.record_findings(org_id, asset_id, scan_id, all_findings)

            secrets_count = sum(1 for f in all_findings if f["category"] == "secret")
            deps_count = sum(1 for f in all_findings if f["category"] == "dependency")
            suspicious_count = sum(1 for f in all_findings if f["category"] == "suspicious_commit")

            stats = {
                "commit_sha": head_sha,
                "total_findings": len(stored_findings),
                "secrets_count": secrets_count,
                "dependencies_count": deps_count,
                "suspicious_count": suspicious_count,
                "components_count": len(components),
            }

            scan_repo.update_scan_status(
                org_id,
                scan_id,
                "completed",
                stats=stats,
                commit_sha=head_sha,
            )

            logger.info("Repo scan %s completed for asset %s (%d findings)", scan_id, asset_id, len(stored_findings))
            return {"status": "completed", "stats": stats, "findings_count": len(stored_findings)}

        except Exception as exc:
            logger.exception("Repo scan %s failed for asset %s: %s", scan_id, asset_id, exc)
            scan_repo.update_scan_status(org_id, scan_id, "failed", error=str(exc))
            return {"status": "failed", "error": str(exc)}


# Strong references to in-flight scan tasks so the event loop never garbage-collects
# them mid-execution (asyncio only holds weak references to tasks).
_BACKGROUND_SCAN_TASKS: set[asyncio.Task[dict[str, Any]]] = set()


def queue_repo_scan(org_id: str, asset_id: str, trigger: str = "manual") -> str:
    """Create a scan record and schedule asynchronous execution."""
    db = Database.get_instance()
    scan_repo = SqliteRepoSecurityRepository(db)
    scan_row = scan_repo.create_scan(org_id, asset_id, trigger=trigger)
    scan_id = scan_row["scan_id"]

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Synchronous caller with no running loop: fail closed instead of leaving
        # the scan queued forever.
        logger.error(
            "Cannot queue repo scan %s (org=%s asset=%s trigger=%s): no running event loop",
            scan_id, org_id, asset_id, trigger,
        )
        scan_repo.update_scan_status(
            org_id,
            scan_id,
            "failed",
            error="Scan could not be scheduled: no running event loop",
        )
        return scan_id

    task = loop.create_task(execute_scan(org_id, asset_id, scan_id))
    _BACKGROUND_SCAN_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_SCAN_TASKS.discard)
    return scan_id


async def rematch_components_job(org_id: str) -> dict[str, Any]:
    """Re-query OSV against existing stored repository components for newly published CVEs."""
    db = Database.get_instance()
    scan_repo = SqliteRepoSecurityRepository(db)
    components = scan_repo.list_components(org_id)

    if not components:
        return {"matched": 0, "new_findings": 0}

    findings = await query_osv_vulnerabilities(components)
    asset_findings_map: dict[str, list[dict[str, Any]]] = {}

    for f in findings:
        # Match finding back to asset_id
        for comp in components:
            if comp["name"] == f.get("details", {}).get("package_name"):
                asset_id = comp["asset_id"]
                asset_findings_map.setdefault(asset_id, []).append(f)
                break

    total_recorded = 0
    for asset_id, a_findings in asset_findings_map.items():
        scan_row = scan_repo.create_scan(org_id, asset_id, trigger="rematch")
        recorded = scan_repo.record_findings(org_id, asset_id, scan_row["scan_id"], a_findings)
        scan_repo.update_scan_status(
            org_id,
            scan_row["scan_id"],
            "completed",
            stats={"total_findings": len(recorded), "rematched": True},
        )
        total_recorded += len(recorded)

    return {"matched": len(components), "new_findings": total_recorded}
