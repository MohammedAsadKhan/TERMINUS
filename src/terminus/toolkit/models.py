"""Strict, non-executing contracts for the defensive toolkit roadmap."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Annotated, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from terminus.orchestration.scheduler_models import JobLease

Id = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")]
Text = Annotated[str, Field(min_length=1, max_length=2000)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
CoreRole = Literal[
    "triage",
    "identity",
    "endpoint",
    "network",
    "response_planner",
    "verification",
    "evidence_reporting",
    "application_api",
]
Availability = Literal[
    "planned", "implementation_pending", "not_configured", "available"
]
Family = Literal[
    "incident_alerts",
    "collection_coverage",
    "identity",
    "endpoint",
    "forensics",
    "network",
    "threat_investigation",
    "email",
    "cloud_infrastructure",
    "applications",
    "software_delivery",
    "data_security",
    "specialized_environments",
    "response_planning",
    "response_execution",
    "recovery",
    "verification",
    "improvement_evidence",
]


class Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        allow_inf_nan=False,
    )

    @field_validator(
        "start",
        "end",
        "timestamp",
        "collected_at",
        "source_timestamp",
        "approval_expires_at",
        "issued_at",
        "dispatched_at",
        check_fields=False,
    )
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps require a timezone")
        return value.astimezone(UTC)


class ToolLimits(Contract):
    window_seconds: int = Field(default=3600, ge=1, le=3600)
    page_size: int = Field(default=200, ge=1, le=200)
    max_pages: int = Field(default=4, ge=1, le=4)
    timeout_seconds: int = Field(default=10, ge=1, le=10)
    max_output_bytes: int = Field(default=65536, ge=1, le=65536)


class ReadQuery(Contract):
    """Named resource references, never model-supplied URLs, paths or DSL."""

    resource_id: Id
    start: datetime
    end: datetime
    page_size: int = Field(default=200, ge=1, le=200)
    max_pages: int = Field(default=4, ge=1, le=4)
    event_kind: Literal[
        "detection",
        "coverage",
        "authentication",
        "process",
        "file",
        "network",
        "application",
        "artifact",
        "configuration",
        "audit",
        "evidence",
        "response",
        "verification",
        "inventory",
    ] = "evidence"

    @model_validator(mode="after")
    def bounded_window(self) -> ReadQuery:
        seconds = (self.end - self.start).total_seconds()
        if not 0 < seconds <= 3600:
            raise ValueError("query window must be positive and at most one hour")
        return self


class ScopedEffect(Contract):
    """Declarative changes using trusted resource references and approved diffs."""

    action: Id
    target_ids: Annotated[tuple[Id, ...], Field(min_length=1, max_length=10)]
    parameter_evidence_id: Id
    duration_seconds: int = Field(ge=1, le=86400)
    undo_strategy: Literal[
        "owned_resource_only", "restore_approved_snapshot", "irreversible"
    ]


class ResponseProposal(Contract):
    proposal_id: Id
    org_id: Id
    incident_id: Id
    task_id: Id
    run_id: Id
    provider_connection_id: Id
    policy_version: Id
    effect: ScopedEffect
    evidence_ids: Annotated[tuple[Id, ...], Field(min_length=1, max_length=100)]
    prerequisites: Annotated[tuple[Text, ...], Field(min_length=1, max_length=20)]
    expected_effect: Text
    anticipated_impact: Text
    verification_requirements: Annotated[
        tuple[Text, ...], Field(min_length=1, max_length=20)
    ]
    health_requirements: Annotated[tuple[Text, ...], Field(min_length=1, max_length=20)]
    approval_expires_at: datetime

    def digest(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class ApprovalBinding(Contract):
    approval_id: Id
    org_id: Id
    incident_id: Id
    proposal_id: Id
    proposal_digest: Digest
    approver_id: Id
    approver_role: Literal["admin"]
    issued_at: datetime
    approval_expires_at: datetime

    @model_validator(mode="after")
    def expiry(self) -> ApprovalBinding:
        if self.approval_expires_at <= self.issued_at:
            raise ValueError("approval expiry must follow issuance")
        return self


class ToolDescriptor(Contract):
    tool_id: Id
    version: Literal["1.0"]
    name: Text
    family: Family
    availability: Availability
    release: Literal["1.0", "future"]
    permitted_roles: tuple[Id, ...]
    connector_ids: tuple[Id, ...]
    input_contract: Literal["read_query", "response_proposal", "scoped_effect"]
    output_contract: Literal["tool_result"]
    effect: Literal["read", "local_analysis", "proposal", "dispatch"]
    resource_scope: Literal["incident"]
    egress: Literal["none", "policy_required"]
    requires_approval: bool
    idempotency_required: bool
    limits: ToolLimits
    acceptance_checks: Annotated[tuple[Text, ...], Field(min_length=1)]
    expected_evidence: Annotated[tuple[Text, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def effects_require_binding(self) -> ToolDescriptor:
        if self.effect == "dispatch" and not (
            self.requires_approval and self.idempotency_required
        ):
            raise ValueError("dispatch requires approval and idempotency")
        if self.effect == "dispatch" and self.input_contract != "scoped_effect":
            raise ValueError("dispatch requires scoped-effect input")
        return self


class ToolExecutionContext(Contract):
    """Trusted server-created context; never accept this from model arguments."""

    org_id: Id
    incident_id: Id
    task_id: Id
    run_id: Id
    role: CoreRole
    granted_tool_ids: tuple[Id, ...]
    permitted_resource_ids: tuple[Id, ...]
    permitted_connector_ids: tuple[Id, ...]
    policy_version: Id
    budget_reservation_id: Id
    invocation_count: int = Field(ge=0, le=20)
    cancelled: bool = False
    egress_authorized: bool = False
    lease: JobLease

    @model_validator(mode="after")
    def lease_scope(self) -> ToolExecutionContext:
        expected = (self.org_id, self.incident_id, self.task_id, self.run_id, self.role)
        actual = (
            self.lease.org_id,
            self.lease.incident_id,
            self.lease.task_id,
            self.lease.run_id,
            self.lease.task.role,
        )
        if actual != expected:
            raise ValueError("context must match the leased task/run/role")
        return self


class EvidenceReference(Contract):
    evidence_id: Id
    org_id: Id
    incident_id: Id
    content_hash: Digest


class Provenance(Contract):
    source_id: Id
    connector_id: Id
    connector_version: Id
    source_event_ids: tuple[Id, ...]
    source_timestamp: datetime
    collected_at: datetime
    query_digest: Digest


class ToolResult(Contract):
    tool_id: Id
    version: Literal["1.0"]
    status: Literal[
        "ok", "empty", "partial", "unavailable", "unsupported", "denied", "error"
    ]
    data: JsonValue = None
    evidence: tuple[EvidenceReference, ...] = ()
    provenance: tuple[Provenance, ...] = ()
    coverage: Literal["complete", "incomplete", "unknown"] = "unknown"
    truncated: bool = False
    gaps: tuple[Text, ...] = ()
    error_code: Id | None = None

    @model_validator(mode="after")
    def honest_outcome(self) -> ToolResult:
        if self.status == "empty" and (
            self.data not in (None, [], {})
            or self.coverage != "complete"
            or self.truncated
        ):
            raise ValueError("empty requires complete collection and an empty result")
        if self.truncated and self.status != "partial":
            raise ValueError("truncated results must be partial")
        if (
            self.status in {"unavailable", "unsupported", "denied", "error"}
            and self.data is not None
        ):
            raise ValueError(
                "failed/unavailable collection must not supply invented data"
            )
        payload = json.dumps(self.model_dump(mode="json"), allow_nan=False).encode()
        if len(payload) > 65536:
            raise ValueError("model-facing result exceeds 64 KiB")
        return self


class ToolInvocation(Contract):
    """Audit envelope contract; persistence and dispatch are later work."""

    invocation_id: Id
    org_id: Id
    incident_id: Id
    task_id: Id
    run_id: Id
    tool_id: Id
    tool_version: Literal["1.0"]
    connector_id: Id | None = None
    connector_version: Id | None = None
    arguments_digest: Digest
    policy_version: Id
    policy_decision: Literal["allowed", "denied"]
    outcome: Literal[
        "ok",
        "empty",
        "partial",
        "unavailable",
        "unsupported",
        "denied",
        "error",
        "unknown",
    ]
    timestamp: datetime
    evidence_ids: tuple[Id, ...] = ()
    proposal_digest: Digest | None = None
    dispatch_intent_id: Id | None = None
    idempotency_key: Id | None = None

    @model_validator(mode="after")
    def uncertain_dispatch_has_intent(self) -> ToolInvocation:
        if self.outcome == "unknown" and not (
            self.proposal_digest and self.dispatch_intent_id and self.idempotency_key
        ):
            raise ValueError("unknown effects require recorded dispatch identity")
        return self


class VerificationObservation(Contract):
    kind: Literal[
        "provider_ack",
        "endpoint_effect",
        "attacker_path",
        "management_health",
        "service_health",
    ]
    collector_run_id: Id
    source_id: Id
    source_timestamp: datetime
    evidence: EvidenceReference
    passed: bool


class VerificationReport(Contract):
    org_id: Id
    incident_id: Id
    proposal_digest: Digest
    dispatch_run_id: Id
    dispatched_at: datetime
    status: Literal["pending", "failed", "unknown", "verified"]
    observations: tuple[VerificationObservation, ...]

    @model_validator(mode="after")
    def independent_checks(self) -> VerificationReport:
        for observation in self.observations:
            if (observation.evidence.org_id, observation.evidence.incident_id) != (
                self.org_id,
                self.incident_id,
            ):
                raise ValueError("verification evidence must match the incident")
        if self.status == "verified":
            checks = {
                observation.kind
                for observation in self.observations
                if observation.passed
                and observation.collector_run_id != self.dispatch_run_id
                and observation.source_timestamp >= self.dispatched_at
            }
            if (
                not {
                    "endpoint_effect",
                    "attacker_path",
                    "management_health",
                    "service_health",
                }
                <= checks
            ):
                raise ValueError(
                    "verified requires independent post-dispatch effect and health checks"
                )
            if any(not item.passed for item in self.observations):
                raise ValueError("failed observations cannot establish verification")
            independent = [
                item for item in self.observations if item.kind != "provider_ack"
            ]
            if len({item.evidence.evidence_id for item in independent}) != len(
                independent
            ):
                raise ValueError(
                    "verification checks require separately recorded evidence"
                )
            endpoint_sources = {
                item.source_id for item in independent if item.kind == "endpoint_effect"
            }
            attacker_sources = {
                item.source_id for item in independent if item.kind == "attacker_path"
            }
            if endpoint_sources & attacker_sources:
                raise ValueError(
                    "endpoint and attacker observations require distinct sources"
                )
        return self
