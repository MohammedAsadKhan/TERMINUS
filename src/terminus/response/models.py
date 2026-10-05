"""Bounded response policy and draft inputs without caller-supplied scope."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from terminus.toolkit.models import Contract, Id, ScopedEffect, Text

OpaqueTargetId = Annotated[
    str, Field(pattern=r"^target:[A-Za-z0-9][A-Za-z0-9_.:-]{0,180}$")
]
ResponseAction = Literal["response.wazuh_ip_block"]


class ResponsePolicy(Contract):
    """Trusted admin provisioned binding; credentials and live I/O are absent."""

    org_id: Id
    incident_id: Id
    version: int = Field(ge=1)
    provider_connection_id: Id
    allowed_actions: Annotated[
        tuple[ResponseAction, ...], Field(min_length=1, max_length=1)
    ]
    allowed_target_ids: Annotated[
        tuple[OpaqueTargetId, ...], Field(min_length=1, max_length=100)
    ]
    max_duration_seconds: int = Field(default=900, ge=1, le=86400)
    max_approval_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    enabled: bool = True
    fixture_only: Literal[True] = True

    @property
    def policy_version(self) -> str:
        return f"response-policy:{self.version}"


class RegisteredTarget(Contract):
    target_id: OpaqueTargetId
    org_id: Id
    incident_id: Id
    provider_connection_id: Id
    protected: bool = False
    management: bool = False


class ParameterBinding(Contract):
    """Exact effect parameters recorded as incident evidence before proposal."""

    action: ResponseAction
    target_ids: Annotated[
        tuple[OpaqueTargetId, ...], Field(min_length=1, max_length=10)
    ]
    provider_connection_id: Id
    policy_version: Id
    duration_seconds: int = Field(ge=1, le=86400)
    undo_strategy: Literal["owned_resource_only"]


class ProposalDraft(Contract):
    """Model/operator input: all durable identities and policy bindings are derived."""

    effect: ScopedEffect
    evidence_ids: Annotated[tuple[Id, ...], Field(min_length=1, max_length=100)]
    prerequisites: Annotated[tuple[Text, ...], Field(min_length=1, max_length=19)]
    expected_effect: Text
    anticipated_impact: Text
    verification_requirements: Annotated[
        tuple[Text, ...], Field(min_length=1, max_length=20)
    ]
    health_requirements: Annotated[tuple[Text, ...], Field(min_length=1, max_length=20)]
    approval_ttl_seconds: int = Field(default=300, ge=1, le=3600)

    @model_validator(mode="after")
    def exact_parameter_reference(self) -> ProposalDraft:
        if self.effect.parameter_evidence_id not in self.evidence_ids:
            raise ValueError("parameter evidence must be included in cited evidence")
        if len(set(self.effect.target_ids)) != len(self.effect.target_ids):
            raise ValueError("target IDs must be unique")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence IDs must be unique")
        return self
