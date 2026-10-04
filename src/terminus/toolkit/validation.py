"""Contract validation helpers, without a dispatcher or provider invocation.

These checks are fixtures for the future gateway, not a complete authorization
service. Server-created grants, credential policy and durable budgets must be
implemented before any adapter may execute.
"""

from __future__ import annotations

import json
from datetime import datetime

from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.storage import OrchestrationStore
from terminus.toolkit.models import (
    ApprovalBinding,
    ReadQuery,
    ResponseProposal,
    ToolDescriptor,
    ToolExecutionContext,
    ToolResult,
)


class ToolContractDeniedError(ValueError):
    """Contract cannot authorize this request or outcome."""


class ToolContractValidator:
    def __init__(self, scheduler: SchedulerStore) -> None:
        self.scheduler = scheduler
        self.records = OrchestrationStore(scheduler.db)

    def validate_request(  # noqa: C901 - independent contract admission checks
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
    ) -> None:
        descriptor = ToolDescriptor.model_validate(descriptor.model_dump())
        context = ToolExecutionContext.model_validate(context.model_dump())
        query = ReadQuery.model_validate(query.model_dump())
        if descriptor.availability != "available" or descriptor.release != "1.0":
            raise ToolContractDeniedError("Tool is unavailable in 1.0")
        if (
            descriptor.effect not in {"read", "local_analysis"}
            or descriptor.input_contract != "read_query"
        ):
            raise ToolContractDeniedError("Read-query contract cannot dispatch effects")
        if (
            context.role not in descriptor.permitted_roles
            or descriptor.tool_id not in context.granted_tool_ids
        ):
            raise ToolContractDeniedError("Role does not have this tool grant")
        if query.resource_id not in context.permitted_resource_ids:
            raise ToolContractDeniedError("Resource is outside trusted scope")
        if not set(descriptor.connector_ids) <= set(context.permitted_connector_ids):
            raise ToolContractDeniedError("Connector is outside trusted scope")
        if context.cancelled or context.invocation_count >= 20:
            raise ToolContractDeniedError("Cancelled or exhausted tool budget")
        if descriptor.egress == "policy_required" and not context.egress_authorized:
            raise ToolContractDeniedError("External data sharing is not authorized")
        if (
            (query.end - query.start).total_seconds() > descriptor.limits.window_seconds
            or query.page_size > descriptor.limits.page_size
            or query.max_pages > descriptor.limits.max_pages
        ):
            raise ToolContractDeniedError("Query exceeds descriptor limits")
        with self.scheduler.db.transaction():
            job = self.scheduler._owned(context.lease, self.scheduler._now())  # noqa: SLF001
            if job.role != context.role:
                raise ToolContractDeniedError(
                    "Context role differs from the persisted job"
                )
            if job.cancellation_requested:
                raise ToolContractDeniedError("Cancellation requested")

    def validate_result(
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        result: ToolResult,
    ) -> None:
        descriptor = ToolDescriptor.model_validate(descriptor.model_dump())
        context = ToolExecutionContext.model_validate(context.model_dump())
        result = ToolResult.model_validate(result.model_dump())
        if (result.tool_id, result.version) != (descriptor.tool_id, descriptor.version):
            raise ToolContractDeniedError("Unexpected result identity")
        if (
            len(json.dumps(result.model_dump(mode="json")).encode())
            > descriptor.limits.max_output_bytes
        ):
            raise ToolContractDeniedError("Result exceeds descriptor output bound")
        if (
            result.status in {"ok", "partial"}
            and result.data is not None
            and (not result.evidence or not result.provenance)
        ):
            raise ToolContractDeniedError(
                "Collected findings require evidence and provenance"
            )
        if any(
            item.connector_id not in context.permitted_connector_ids
            or item.connector_id not in descriptor.connector_ids
            for item in result.provenance
        ):
            raise ToolContractDeniedError(
                "Result provenance uses an unauthorized connector"
            )
        for ref in result.evidence:
            if (ref.org_id, ref.incident_id) != (context.org_id, context.incident_id):
                raise ToolContractDeniedError("Cross-tenant or cross-incident evidence")
            evidence = self.records.get_evidence(context.org_id, ref.evidence_id)
            if evidence.incident_id != context.incident_id:
                raise ToolContractDeniedError("Evidence is outside the incident")
            if evidence.content_hash != ref.content_hash:
                raise ToolContractDeniedError("Evidence content hash does not match")


def validate_approval(
    proposal: ResponseProposal,
    approval: ApprovalBinding,
    *,
    now: datetime,
    requester_id: str,
    current_policy_version: str,
) -> None:
    proposal = ResponseProposal.model_validate(proposal.model_dump())
    approval = ApprovalBinding.model_validate(approval.model_dump())
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("approval checks require an aware current time")
    if approval.approver_id == requester_id:
        raise ToolContractDeniedError("Self-approval is forbidden")
    if (approval.org_id, approval.incident_id, approval.proposal_id) != (
        proposal.org_id,
        proposal.incident_id,
        proposal.proposal_id,
    ) or approval.proposal_digest != proposal.digest():
        raise ToolContractDeniedError("Approval does not match the immutable proposal")
    if proposal.policy_version != current_policy_version:
        raise ToolContractDeniedError("Policy changed; fresh approval required")
    if now < approval.issued_at or now >= min(
        approval.approval_expires_at, proposal.approval_expires_at
    ):
        raise ToolContractDeniedError("Approval is not currently valid")
