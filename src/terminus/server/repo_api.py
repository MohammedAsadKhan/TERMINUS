"""API endpoints for repository security scans, findings, SBOM components, and GitHub webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from terminus.core.ids import OrgId
from terminus.repo_security.models import FindingCategory, FindingSeverity, FindingStatus
from terminus.repo_security.runner import execute_scan, queue_repo_scan, rematch_components_job
from terminus.repo_security.storage import SqliteRepoSecurityRepository
from terminus.server.deps import get_current_org, require_admin, require_operator
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database

repo_router = APIRouter(tags=["repo-security"])


def _check_feature_enabled() -> None:
    if os.getenv("TERMINUS_REPO_SCAN_ENABLED", "").lower() not in ("1", "true"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Repository security module is not enabled",
        )


def get_repo_security_repository() -> SqliteRepoSecurityRepository:
    return SqliteRepoSecurityRepository()


def get_asset_repository() -> SqliteAssetRepository:
    return SqliteAssetRepository()


class UpdateFindingStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    note: str | None = Field(default=None, max_length=1000)


@repo_router.post(
    "/assets/{asset_id}/scan",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(_check_feature_enabled), Depends(require_operator)],
)
async def trigger_asset_scan(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    asset_repo: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    scan_repo: Annotated[SqliteRepoSecurityRepository, Depends(get_repo_security_repository)],
) -> dict[str, Any]:
    asset = asset_repo.get(str(org_id), asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if asset.get("kind") != "repository":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asset is not a repository")

    scan_id = queue_repo_scan(str(org_id), asset_id, trigger="manual")
    return {"status": "accepted", "scan_id": scan_id, "asset_id": asset_id}


@repo_router.get(
    "/assets/{asset_id}/scans",
    dependencies=[Depends(_check_feature_enabled), Depends(require_operator)],
)
async def list_asset_scans(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    asset_repo: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    scan_repo: Annotated[SqliteRepoSecurityRepository, Depends(get_repo_security_repository)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    asset = asset_repo.get(str(org_id), asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return scan_repo.list_scans(str(org_id), asset_id, limit=limit, offset=offset)


@repo_router.get(
    "/assets/{asset_id}/findings",
    dependencies=[Depends(_check_feature_enabled), Depends(require_operator)],
)
async def list_asset_findings(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    asset_repo: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    scan_repo: Annotated[SqliteRepoSecurityRepository, Depends(get_repo_security_repository)],
    severity: Annotated[FindingSeverity | None, Query()] = None,
    status: Annotated[FindingStatus | None, Query()] = None,
    category: Annotated[FindingCategory | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    asset = asset_repo.get(str(org_id), asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return scan_repo.list_findings(
        str(org_id),
        asset_id=asset_id,
        severity=severity,
        status=status,
        category=category,
        limit=limit,
        offset=offset,
    )


@repo_router.get(
    "/assets/{asset_id}/components",
    dependencies=[Depends(_check_feature_enabled), Depends(require_operator)],
)
async def list_asset_components(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    asset_repo: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    scan_repo: Annotated[SqliteRepoSecurityRepository, Depends(get_repo_security_repository)],
    limit: Annotated[int, Query(ge=1, le=200)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    asset = asset_repo.get(str(org_id), asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return scan_repo.list_components(str(org_id), asset_id=asset_id, limit=limit, offset=offset)


@repo_router.patch(
    "/repo-findings/{finding_id}",
    dependencies=[Depends(_check_feature_enabled), Depends(require_admin)],
)
async def update_finding_status(
    finding_id: str,
    request: UpdateFindingStatusRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    scan_repo: Annotated[SqliteRepoSecurityRepository, Depends(get_repo_security_repository)],
) -> dict[str, Any]:
    details = {"note": request.note} if request.note else {}
    updated = scan_repo.update_finding_status(
        str(org_id),
        finding_id,
        request.status,
        actor="admin",
        details=details,
    )
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return updated


@repo_router.post(
    "/repos/rematch",
    dependencies=[Depends(_check_feature_enabled), Depends(require_admin)],
)
async def trigger_components_rematch(
    org_id: Annotated[OrgId, Depends(get_current_org)],
) -> dict[str, Any]:
    result = await rematch_components_job(str(org_id))
    return {"status": "completed", **result}


def _resolve_webhook_org(db: Database, clone_urls: list[str]) -> str | None:
    """Determine the org a webhook delivery targets, entirely server-side.

    Prefers the configured tenant (TERMINUS_GITHUB_WEBHOOK_ORG_ID). Otherwise falls
    back to single-tenant derivation: the matching assets' org, but only when every
    match belongs to exactly one org. Ambiguous multi-org matches fail closed.
    """
    configured_org = os.getenv("TERMINUS_GITHUB_WEBHOOK_ORG_ID", "").strip()
    if configured_org:
        return configured_org

    rows = db.fetchall("SELECT org_id, locator FROM assets WHERE kind = 'repository'")
    matching_orgs = {
        str(row["org_id"])
        for row in rows
        if (row.get("locator") or "").rstrip("/").lower() in clone_urls
    }
    if len(matching_orgs) == 1:
        return matching_orgs.pop()
    return None


def _match_repo_asset_in_org(db: Database, org_id: str, clone_urls: list[str]) -> dict[str, Any] | None:
    """Resolve the repository asset strictly within the given org."""
    for url in clone_urls:
        row = db.fetchone(
            "SELECT * FROM assets WHERE org_id = ? AND kind = 'repository' AND locator = ?",
            (org_id, url),
        )
        if row is not None:
            return row
    # Stored locators may differ from the payload URL by case or trailing slash.
    candidates = db.fetchall(
        "SELECT * FROM assets WHERE org_id = ? AND kind = 'repository'",
        (org_id,),
    )
    for asset in candidates:
        loc = (asset.get("locator") or "").rstrip("/").lower()
        if loc and loc in clone_urls:
            return asset
    return None


@repo_router.post(
    "/repos/webhook/github",
    dependencies=[Depends(_check_feature_enabled)],
)
async def github_repo_webhook(
    request: Request,
    x_hub_signature_256: Annotated[str | None, Header(alias="X-Hub-Signature-256")] = None,
    x_github_event: Annotated[str | None, Header(alias="X-GitHub-Event")] = None,
) -> dict[str, Any]:
    webhook_secret = os.getenv("TERMINUS_GITHUB_WEBHOOK_SECRET", "")
    if not webhook_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Webhook signature verification failed")

    if not x_hub_signature_256:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing signature header")

    body_bytes = await request.body()

    expected_sig = "sha256=" + hmac.new(
        webhook_secret.encode("utf-8"), body_bytes, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, x_hub_signature_256):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid webhook signature")

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload")

    # Extract repository URL
    repo_info = payload.get("repository", {})
    clone_urls = [
        repo_info.get("clone_url"),
        repo_info.get("html_url"),
        repo_info.get("url"),
    ]
    clone_urls = [u.rstrip("/").lower() for u in clone_urls if u]

    if not clone_urls:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")

    # Resolve org server-side (never trust an external header!), then resolve the
    # asset strictly within that org - never across all orgs.
    db = Database.get_instance()
    org_id = _resolve_webhook_org(db, clone_urls)
    if org_id is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not registered as an asset")

    matched_asset = _match_repo_asset_in_org(db, org_id, clone_urls)
    if matched_asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not registered as an asset")

    org_id = matched_asset["org_id"]
    asset_id = matched_asset["asset_id"]

    scan_id = queue_repo_scan(org_id, asset_id, trigger="push")
    return {"status": "queued", "scan_id": scan_id, "asset_id": asset_id, "org_id": org_id}


@repo_router.post(
    "/demo/seed-inventory",
    dependencies=[Depends(require_operator)],
)
async def seed_demo_inventory(
    org_id: Annotated[OrgId, Depends(get_current_org)],
) -> dict[str, Any]:
    from terminus.demos.seed_data import seed_presentation_demo_data

    return seed_presentation_demo_data(org_id=str(org_id))


@repo_router.post(
    "/demo/simulate-webhook",
    dependencies=[Depends(require_operator)],
)
async def simulate_repo_webhook(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    asset_id: str | None = None,
) -> dict[str, Any]:
    db = Database.get_instance()
    asset_repo = SqliteAssetRepository(db)
    if asset_id:
        asset = asset_repo.get(str(org_id), asset_id)
    else:
        repos = asset_repo.list_for_org(str(org_id), kind="repository", limit=1)
        asset = repos[0] if repos else None

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No repository asset found in organization to trigger webhook",
        )

    scan_id = queue_repo_scan(str(org_id), asset["asset_id"], trigger="push")
    return {
        "status": "queued",
        "trigger": "simulated_github_push",
        "scan_id": scan_id,
        "asset_name": asset["name"],
        "locator": asset["locator"],
    }
