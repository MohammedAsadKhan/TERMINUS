"""Authenticated, organization-scoped model connection metadata API."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Annotated, Any, override

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError

from terminus.auth.models import User
from terminus.config import Settings, get_settings
from terminus.core.ids import OrgId
from terminus.model_gateway import (
    ConnectionConflictError,
    ConnectionDeniedError,
    ConnectionNotFoundError,
    ConnectionUnavailableError,
    ConnectionValidationError,
    CredentialCipher,
    ModelConnectionCreate,
    ModelConnectionStore,
    ModelConnectionUpdate,
    ModelConnectionView,
)
from terminus.server.deps import get_current_org, get_current_user, require_admin
from terminus.storage.db import Database


class RedactedValidationRoute(APIRoute):
    """Keep attacker-controlled request values out of validation responses."""

    @override
    def get_route_handler(
        self,
    ) -> Callable[[Request], Coroutine[Any, Any, Response]]:  # pyright: ignore[reportExplicitAny] - matches FastAPI's override contract
        original = super().get_route_handler()

        async def redacted_handler(request: Request) -> Response:
            try:
                return await original(request)
            except RequestValidationError:
                return JSONResponse(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    content={"detail": "Invalid model connection request"},
                )

        return redacted_handler


router = APIRouter(
    prefix="/model-connections",
    tags=["model-connections"],
    route_class=RedactedValidationRoute,
)


def get_model_connection_store(
    settings: Annotated[Settings, Depends(get_settings)],
) -> ModelConnectionStore:
    """Build a store using the process-external model credential key, when set."""
    cipher = None
    key = settings.model_credentials_key.get_secret_value()
    if key:
        try:
            cipher = CredentialCipher.from_key(key)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Model connection storage is unavailable",
            ) from None
    try:
        return ModelConnectionStore(Database.get_instance(), cipher=cipher)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model connection storage is unavailable",
        ) from None


def _request[RequestModel: BaseModel](
    model: type[RequestModel], payload: object
) -> RequestModel:
    """Validate a request without returning attacker-controlled values in errors."""
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid model connection request",
        ) from None


def _store_error(exc: Exception) -> HTTPException:
    """Translate model connection errors without exposing persistence diagnostics."""
    if isinstance(exc, ConnectionDeniedError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Model connection operation is not permitted",
        )
    if isinstance(exc, ConnectionNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model connection not found",
        )
    if isinstance(exc, ConnectionConflictError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Model connection update conflict",
        )
    if isinstance(exc, ConnectionUnavailableError):
        return HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model connection storage is unavailable",
        )
    if isinstance(exc, ConnectionValidationError):
        return HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid model connection request",
        )
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Model connection storage is unavailable",
    )


@router.get("", response_model=list[ModelConnectionView])
def list_model_connections(
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> list[ModelConnectionView]:
    try:
        return store.list_for_org(str(org_id), str(user.user_id))
    except Exception as exc:
        raise _store_error(exc) from None


@router.get("/{connection_id}", response_model=ModelConnectionView)
def get_model_connection(
    connection_id: str,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> ModelConnectionView:
    try:
        return store.get(str(org_id), str(user.user_id), connection_id)
    except Exception as exc:
        raise _store_error(exc) from None


@router.post(
    "",
    response_model=ModelConnectionView,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_model_connection(
    payload: Annotated[object, Body()],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> ModelConnectionView:
    request = _request(ModelConnectionCreate, payload)
    try:
        return store.create(str(org_id), str(user.user_id), request)
    except Exception as exc:
        raise _store_error(exc) from None


@router.patch(
    "/{connection_id}",
    response_model=ModelConnectionView,
    dependencies=[Depends(require_admin)],
)
def update_model_connection(
    connection_id: str,
    payload: Annotated[object, Body()],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> ModelConnectionView:
    request = _request(ModelConnectionUpdate, payload)
    try:
        return store.update(str(org_id), str(user.user_id), connection_id, request)
    except Exception as exc:
        raise _store_error(exc) from None


@router.delete(
    "/{connection_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin)],
)
def delete_model_connection(
    connection_id: str,
    expected_version: Annotated[int, Query(ge=1)],
    org_id: Annotated[OrgId, Depends(get_current_org)],
    user: Annotated[User, Depends(get_current_user)],
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> None:
    try:
        store.delete(
            str(org_id),
            str(user.user_id),
            connection_id,
            expected_version,
        )
    except Exception as exc:
        raise _store_error(exc) from None
