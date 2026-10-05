"""Read-only roadmap metadata, deliberately separate from execution authority."""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import JsonValue

from terminus.core.ids import OrgId
from terminus.server.deps import get_current_org
from terminus.toolkit.catalog import load_catalog

router = APIRouter(prefix="/orchestration", tags=["orchestration"])


@router.get("/catalog")
def specialist_catalog(
    _org: Annotated[OrgId, Depends(get_current_org)],
) -> dict[str, JsonValue]:
    catalog = load_catalog()
    return {
        "items": [
            {
                "specialty_id": item.specialty_id,
                "name": item.name,
                "area": item.area,
                "core_role": item.core_role,
                "availability": item.availability,
                "release": "1.0" if item.core_role is not None else "future",
                "execution_available": False,
                "status_label": f"Covered by {item.core_role}; not separately launchable"
                if item.core_role is not None
                else "Planned — unavailable in 1.0",
            }
            for item in catalog.specialties
        ],
        "note": "Catalog registration is not operational capability. Actual activity comes from durable task/run records.",
    }
