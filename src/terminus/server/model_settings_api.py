"""Tenant-scoped model policy and financial settings; no execution endpoints."""

from __future__ import annotations

import json
from typing import Annotated, ClassVar, cast

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError

from terminus.auth.models import User
from terminus.config import Settings, get_settings
from terminus.core.ids import OrgId
from terminus.model_gateway.ledger import (
    BudgetConflictError,
    BudgetDeniedError,
    ModelBudgetStore,
    ModelPrice,
    UsageSummary,
)
from terminus.model_gateway.models import ModelConnectionView
from terminus.model_gateway.policy import (
    DataClassification,
    EvidenceClassification,
    ModelPolicy,
    ModelPolicyConflictError,
    ModelPolicyDeniedError,
    ModelPolicyNotFoundError,
    ModelPolicyStore,
    ModelPolicyWrite,
)
from terminus.model_gateway.secrets import CredentialCipher
from terminus.model_gateway.store import ModelConnectionStore
from terminus.server.deps import get_current_org, get_current_user, require_admin
from terminus.server.model_connections_api import (
    RedactedValidationRoute,
    get_model_connection_store,
)
from terminus.storage.db import Database

router = APIRouter(
    prefix="/model-settings",
    tags=["model-settings"],
    route_class=RedactedValidationRoute,
)
Org = Annotated[OrgId, Depends(get_current_org)]
Actor = Annotated[User, Depends(get_current_user)]
Admin = Annotated[None, Depends(require_admin)]
Payload = Annotated[dict[str, JsonValue], Body()]


class BudgetWrite(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)
    expected_version: int = Field(default=0, ge=0)
    limit_micro_usd: int = Field(ge=0, le=10**18)
    limit_tokens: int | None = Field(default=None, ge=0, le=10**18)


class PriceWrite(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)
    expected_version: int = Field(default=0, ge=0)
    input_per_mtok_micro_usd: int = Field(ge=0)
    output_per_mtok_micro_usd: int = Field(ge=0)
    cached_input_per_mtok_micro_usd: int | None = Field(default=None, ge=0)
    reasoning_per_mtok_micro_usd: int | None = Field(default=None, ge=0)


class ClassificationWrite(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid", strict=True)
    expected_version: int = Field(default=0, ge=0)
    classification: DataClassification


def _parse[T: BaseModel](model: type[T], payload: object) -> T:
    try:
        return model.model_validate_json(json.dumps(payload, allow_nan=False))
    except (ValidationError, ValueError, TypeError):
        raise HTTPException(422, "Invalid model settings request") from None


def _error(exc: Exception) -> HTTPException:
    if isinstance(exc, (BudgetDeniedError, ModelPolicyDeniedError, PermissionError)):
        return HTTPException(403, "Model settings operation is not permitted")
    if isinstance(exc, (BudgetConflictError, ModelPolicyConflictError)):
        return HTTPException(409, "Model settings version conflict")
    if isinstance(exc, (ModelPolicyNotFoundError, LookupError)):
        return HTTPException(404, "Model settings record not found")
    if isinstance(exc, ValueError):
        return HTTPException(422, "Invalid model settings request")
    return HTTPException(503, "Model settings are unavailable")


def _policy() -> ModelPolicyStore:
    return ModelPolicyStore(Database.get_instance())


def _budgets() -> ModelBudgetStore:
    return ModelBudgetStore(Database.get_instance())


@router.get("/status")
def configuration_status(
    org: Org, actor: Actor, settings: Annotated[Settings, Depends(get_settings)]
) -> dict[str, JsonValue]:
    # This reports configuration prerequisites, never connectivity or protection.
    ready = False
    if settings.model_credentials_key.get_secret_value():
        try:
            _ = CredentialCipher.from_key(
                settings.model_credentials_key.get_secret_value()
            )
            ready = True
        except ValueError:
            ready = False
    try:
        connections = ModelConnectionStore(Database.get_instance(), None).list_for_org(
            str(org), str(actor.user_id)
        )
        return {
            "credential_storage_ready": ready,
            "registered_connections": len(connections),
            "live_validation": "not established by configuration",
            "setup_required": []
            if ready
            else [
                "Configure TERMINUS_MODEL_CREDENTIALS_KEY in the server and specialist processes."
            ],
        }
    except Exception as exc:
        raise _error(exc) from None


@router.get("/policy", response_model=ModelPolicy)
def get_policy(org: Org, actor: Actor) -> ModelPolicy:
    try:
        return _policy().get(str(org), str(actor.user_id))
    except Exception as exc:
        raise _error(exc) from None


@router.put("/policy", response_model=ModelPolicy)
def put_policy(org: Org, actor: Actor, _admin: Admin, payload: Payload) -> ModelPolicy:
    try:
        return _policy().put(
            str(org), str(actor.user_id), _parse(ModelPolicyWrite, payload)
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _error(exc) from None


@router.get("/usage/{window}", response_model=UsageSummary)
def get_usage(window: str, org: Org, actor: Actor) -> UsageSummary:
    try:
        return _budgets().usage_summary(str(org), str(actor.user_id), window)
    except Exception as exc:
        raise _error(exc) from None


@router.get("/budget/{window}")
def get_budget(window: str, org: Org, actor: Actor) -> dict[str, JsonValue]:
    try:
        budgets = _budgets()
        with budgets.db.transaction():
            _ = budgets.usage_summary(str(org), str(actor.user_id), window)
            row = budgets.db.fetchone(
                "SELECT window_key,limit_micro_usd,limit_tokens,version FROM model_budgets WHERE org_id=? AND window_key=?",
                (str(org), window),
            )
            if row is None:
                raise LookupError("Missing budget")
            return {
                "window_key": str(cast("str", row["window_key"])),
                "limit_micro_usd": int(cast("int", row["limit_micro_usd"])),
                "limit_tokens": None
                if row["limit_tokens"] is None
                else int(cast("int", row["limit_tokens"])),
                "version": int(cast("int", row["version"])),
            }
    except Exception as exc:
        raise _error(exc) from None


@router.put("/budget/{window}")
def put_budget(
    window: str, org: Org, actor: Actor, _admin: Admin, payload: Payload
) -> dict[str, JsonValue]:
    request = _parse(BudgetWrite, payload)
    try:
        record = _budgets().put_budget(
            str(org),
            str(actor.user_id),
            window,
            limit_micro_usd=request.limit_micro_usd,
            limit_tokens=request.limit_tokens,
            expected_version=request.expected_version,
        )
        return record.model_dump(mode="json")
    except Exception as exc:
        raise _error(exc) from None


def _connection(
    store: ModelConnectionStore, org: Org, actor: Actor, connection_id: str, model: str
) -> ModelConnectionView:
    connection = store.get(str(org), str(actor.user_id), connection_id)
    if model not in connection.models:
        raise LookupError("Model is not registered")
    return connection


@router.get("/prices/{connection_id}/{model:path}", response_model=ModelPrice)
def get_price(
    connection_id: str,
    model: str,
    org: Org,
    actor: Actor,
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> ModelPrice:
    try:
        _ = _connection(store, org, actor, connection_id, model)
        return _budgets().get_price(str(org), str(actor.user_id), connection_id, model)
    except Exception as exc:
        raise _error(exc) from None


@router.put("/prices/{connection_id}/{model:path}", response_model=ModelPrice)
def put_price(
    connection_id: str,
    model: str,
    org: Org,
    actor: Actor,
    _admin: Admin,
    payload: Payload,
    store: Annotated[ModelConnectionStore, Depends(get_model_connection_store)],
) -> ModelPrice:
    request = _parse(PriceWrite, payload)
    try:
        with store.db.transaction():
            _ = _connection(store, org, actor, connection_id, model)
            return _budgets().put_price(
                str(org),
                str(actor.user_id),
                connection_id,
                model,
                input_per_mtok_micro_usd=request.input_per_mtok_micro_usd,
                output_per_mtok_micro_usd=request.output_per_mtok_micro_usd,
                cached_input_per_mtok_micro_usd=request.cached_input_per_mtok_micro_usd,
                reasoning_per_mtok_micro_usd=request.reasoning_per_mtok_micro_usd,
                expected_version=request.expected_version,
            )
    except Exception as exc:
        raise _error(exc) from None


@router.put(
    "/evidence/{evidence_id}/classification", response_model=EvidenceClassification
)
def classify_evidence(
    evidence_id: str, org: Org, actor: Actor, _admin: Admin, payload: Payload
) -> EvidenceClassification:
    request = _parse(ClassificationWrite, payload)
    try:
        return _policy().classify_evidence(
            str(org),
            str(actor.user_id),
            evidence_id,
            request.classification,
            expected_version=request.expected_version,
        )
    except Exception as exc:
        raise _error(exc) from None
