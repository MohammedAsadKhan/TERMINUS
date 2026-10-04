"""Fenced, bounded evidence collection for trusted installed read handlers.

This writer has no provider, filesystem or model interface. Source records stay
inside the incident; model egress still requires the later redaction gateway.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from pydantic import JsonValue, TypeAdapter

from terminus.toolkit.audit import ToolInvocationStore
from terminus.toolkit.models import (
    EvidenceReference,
    Provenance,
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
)
from terminus.toolkit.validation import ToolContractDeniedError, ToolContractValidator

_JSON = TypeAdapter[JsonValue](JsonValue)


def query_digest(query: ReadQuery) -> str:
    """Canonical arguments identity shared by collection and invocation audit."""
    query = ReadQuery.model_validate(query.model_dump())
    encoded = json.dumps(
        query.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


class ToolEvidenceWriter:
    """Persist only observed, scoped records while the collector owns its job."""

    def __init__(
        self, validator: ToolContractValidator, audit: ToolInvocationStore
    ) -> None:
        if validator.scheduler.db is not audit.db:
            raise ValueError("Evidence and audit must use the same database")
        self.validator: ToolContractValidator = validator
        self.audit: ToolInvocationStore = audit

    def record(
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
        *,
        connector_id: str,
        connector_version: str,
        source_id: str,
        source_timestamp: datetime,
        content: JsonValue,
        source_event_ids: tuple[str, ...] = (),
    ) -> tuple[EvidenceReference, Provenance]:
        descriptor = ToolDescriptor.model_validate(descriptor.model_dump())
        context = ToolExecutionContext.model_validate(context.model_dump())
        query = ReadQuery.model_validate(query.model_dump())
        if connector_id not in descriptor.connector_ids:
            raise ToolContractDeniedError("Evidence connector is outside the tool")
        if content is None:
            raise ToolContractDeniedError("Missing telemetry is a gap, not evidence")
        if len(source_event_ids) > query.page_size * query.max_pages:
            raise ToolContractDeniedError("Source event count exceeds query bounds")
        content = _JSON.validate_python(content, strict=True)
        provenance = Provenance(
            source_id=source_id,
            connector_id=connector_id,
            connector_version=connector_version,
            source_event_ids=source_event_ids,
            source_timestamp=source_timestamp,
            collected_at=self.audit.clock(),
            query_digest=query_digest(query),
        )
        if not query.start <= provenance.source_timestamp <= query.end:
            raise ToolContractDeniedError("Evidence timestamp is outside the query")
        envelope: JsonValue = {
            "tool_id": descriptor.tool_id,
            "tool_version": descriptor.version,
            "invocation_id": context.invocation_id,
            "run_id": context.run_id,
            "resource_id": query.resource_id,
            "provenance": provenance.model_dump(mode="json"),
            "observed": content,
        }
        if (
            len(json.dumps(envelope, allow_nan=False).encode())
            > descriptor.limits.max_output_bytes
        ):
            raise ToolContractDeniedError("Evidence envelope exceeds the tool bound")
        with self.validator.scheduler.db.transaction():
            self.validator.validate_request(descriptor, context, query)
            _ = self.audit.assert_pending(context, descriptor, query)
            evidence = self.validator.records.create_evidence(
                context.org_id,
                context.task_id,
                provenance.source_id,
                provenance.source_timestamp,
                content=envelope,
            )
        return (
            EvidenceReference(
                evidence_id=evidence.evidence_id,
                org_id=evidence.org_id,
                incident_id=evidence.incident_id,
                content_hash=evidence.content_hash,
            ),
            provenance,
        )
