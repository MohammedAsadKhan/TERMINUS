"""Inventory metadata API. Endpoints never contact the referenced asset."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from terminus.core.ids import OrgId
from terminus.repo_security.sandbox import is_local_path_locator
from terminus.server.deps import get_current_org, require_admin
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database

AssetKind = Literal["repository", "container", "cloud", "virtual_machine", "domain", "device"]
AssetCriticality = Literal["tier0", "tier1", "tier2", "tier3"]
AssetExposure = Literal["internal", "internet"]

router = APIRouter(prefix="/assets", tags=["assets"])
_CREDENTIAL_MARKERS = re.compile(
    r"(?i)(?:\bbearer\s+[a-z0-9._~-]{8,}|\b(?:api[_ -]?key|password|passwd|secret|token)\s*[:=])"
)
_ALLOWED_REPO_HOSTS = {"github.com", "gitlab.com"}


def get_asset_repository() -> SqliteAssetRepository:
    return SqliteAssetRepository()


def _validate_repo_locator(locator: str | None) -> None:
    if not locator:
        return
    allow_local = (
        os.getenv("TERMINUS_DEPLOYMENT_MODE") == "local"
        and os.getenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL") == "true"
    )
    # Local escape hatch: bare filesystem paths and file:// URLs only. Remote URLs
    # are never exempt - they always run the https/allowlist checks below.
    if allow_local and is_local_path_locator(locator):
        return
    parsed = urlsplit(locator)
    if parsed.scheme.lower() != "https":
        raise HTTPException(
            status_code=422,
            detail="Repository locator must be a valid https:// URL on an allowlisted host",
        )
    host = (parsed.hostname or "").lower()
    if not host or host not in _ALLOWED_REPO_HOSTS:
        raise HTTPException(
            status_code=422,
            detail=f"Repository host '{host}' is not on the allowlist ({', '.join(sorted(_ALLOWED_REPO_HOSTS))})",
        )


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AssetKind
    name: str = Field(min_length=1, max_length=200)
    locator: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=2000)
    agent_id: str | None = Field(default=None, max_length=100)
    hostname: str | None = Field(default=None, max_length=255)
    criticality: AssetCriticality | None = None
    owner: str | None = Field(default=None, max_length=200)
    environment: str | None = Field(default=None, max_length=100)
    exposure: AssetExposure | None = None

    @field_validator("name", "locator", "notes", "agent_id", "hostname", "owner", "environment")
    @classmethod
    def plain_inventory_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            if value == "":
                return None
            raise ValueError("must not contain only whitespace")
        if _CREDENTIAL_MARKERS.search(cleaned):
            raise ValueError("credentials and secrets cannot be stored in asset metadata")
        return cleaned


class AssetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    locator: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=2000)
    agent_id: str | None = Field(default=None, max_length=100)
    hostname: str | None = Field(default=None, max_length=255)
    criticality: AssetCriticality | None = None
    owner: str | None = Field(default=None, max_length=200)
    environment: str | None = Field(default=None, max_length=100)
    exposure: AssetExposure | None = None

    @field_validator("name", "locator", "notes", "agent_id", "hostname", "owner", "environment")
    @classmethod
    def plain_inventory_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if _CREDENTIAL_MARKERS.search(cleaned):
            raise ValueError("credentials and secrets cannot be stored in asset metadata")
        return cleaned


def _compute_coverage(db: Database, org_id: str, row: dict[str, Any]) -> str:
    if row.get("kind") != "repository":
        return "not_connected"
    asset_id = str(row.get("asset_id"))
    latest_scan = db.fetchone(
        "SELECT status, finished_at FROM repo_scans WHERE org_id = ? AND asset_id = ? "
        "ORDER BY started_at DESC, scan_id DESC LIMIT 1",
        (str(org_id), asset_id),
    )
    if not latest_scan:
        return "never_scanned"
    if latest_scan["status"] == "failed":
        return "scan_failed"
    if latest_scan["status"] == "completed":
        finished_at = latest_scan["finished_at"]
        if finished_at:
            try:
                dt = datetime.fromisoformat(finished_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                age = (datetime.now(UTC) - dt).total_seconds()
                return "scanned" if age <= 7 * 86400 else "stale"
            except Exception:
                return "scanned"
        return "scanned"
    last_completed = db.fetchone(
        "SELECT finished_at FROM repo_scans WHERE org_id = ? AND asset_id = ? AND status = 'completed' "
        "ORDER BY finished_at DESC LIMIT 1",
        (str(org_id), asset_id),
    )
    if last_completed and last_completed["finished_at"]:
        try:
            dt = datetime.fromisoformat(last_completed["finished_at"])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            age = (datetime.now(UTC) - dt).total_seconds()
            return "scanned" if age <= 7 * 86400 else "stale"
        except Exception:
            return "scanned"
    return "never_scanned"


def _response(repository: SqliteAssetRepository, org_id: str, row: dict[str, Any]) -> dict[str, Any]:
    coverage = _compute_coverage(repository.db, org_id, row)
    return {**row, "coverage": coverage}


@router.get("")
async def list_assets(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    kind: Annotated[AssetKind | None, Query()] = None,
    q: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, Any]]:
    rows = repository.list_for_org(str(org_id), kind=kind, q=q, limit=limit, offset=offset)
    return [_response(repository, str(org_id), row) for row in rows]


@router.get("/{asset_id}")
async def get_asset(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> dict[str, Any]:
    row = repository.get(str(org_id), asset_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return _response(repository, str(org_id), row)


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def create_asset(
    request: AssetCreate,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> dict[str, Any]:
    if request.kind == "repository":
        _validate_repo_locator(request.locator)

    row = repository.create(
        str(org_id),
        request.kind,
        request.name,
        request.locator,
        request.notes,
        agent_id=request.agent_id,
        hostname=request.hostname,
        criticality=request.criticality,
        owner=request.owner,
        environment=request.environment,
        exposure=request.exposure,
    )

    # Auto-scan repository asset on add if feature enabled
    if request.kind == "repository" and os.getenv("TERMINUS_REPO_SCAN_ENABLED", "").lower() in {"1", "true"}:
        try:
            from terminus.repo_security.runner import queue_repo_scan
            queue_repo_scan(str(org_id), row["asset_id"], trigger="add")
        except Exception:
            pass

    return _response(repository, str(org_id), row)


@router.patch("/{asset_id}", dependencies=[Depends(require_admin)])
async def update_asset(
    asset_id: str,
    request: AssetUpdate,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> dict[str, Any]:
    existing = repository.get(str(org_id), asset_id)
    if existing is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    updates = request.model_dump(exclude_unset=True)
    if "locator" in updates and existing.get("kind") == "repository":
        _validate_repo_locator(updates["locator"])

    updated = repository.update(str(org_id), asset_id, updates)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return _response(repository, str(org_id), updated)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
async def delete_asset(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> None:
    if not repository.delete(str(org_id), asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

