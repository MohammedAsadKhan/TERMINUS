"""Inventory metadata API. Endpoints never contact the referenced asset."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from terminus.core.ids import OrgId
from terminus.server.deps import get_current_org, require_admin
from terminus.storage.assets import SqliteAssetRepository

AssetKind = Literal["repository", "container", "cloud", "virtual_machine", "domain", "device"]

router = APIRouter(prefix="/assets", tags=["assets"])
_CREDENTIAL_MARKERS = re.compile(
    r"(?i)(?:\bbearer\s+[a-z0-9._~-]{8,}|\b(?:api[_ -]?key|password|passwd|secret|token)\s*[:=])"
)


def get_asset_repository() -> SqliteAssetRepository:
    return SqliteAssetRepository()


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AssetKind
    name: str = Field(min_length=1, max_length=200)
    locator: str | None = Field(default=None, max_length=500)
    notes: str | None = Field(default=None, max_length=2000)

    @field_validator("name", "locator", "notes")
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


def _response(row: dict[str, str | None]) -> dict[str, str | None]:
    return {**row, "coverage": "not_connected"}


@router.get("")
async def list_assets(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
    kind: Annotated[AssetKind | None, Query()] = None,
) -> list[dict[str, str | None]]:
    return [_response(row) for row in repository.list_for_org(str(org_id), kind)]


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
async def create_asset(
    request: AssetCreate,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> dict[str, str | None]:
    row = repository.create(
        str(org_id), request.kind, request.name, request.locator, request.notes
    )
    return _response(row)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_admin)])
async def delete_asset(
    asset_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    repository: Annotated[SqliteAssetRepository, Depends(get_asset_repository)],
) -> None:
    if not repository.delete(str(org_id), asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
