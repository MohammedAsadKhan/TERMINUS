"""Opt-in tenant-bound readers composed behind durable tool admission.

The actor and lease come from trusted server/scheduler code. This library adds
no public route, default credentials, model egress or response dispatcher.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast

from pydantic import JsonValue, TypeAdapter

from terminus.orchestration.scheduler_models import JobLease
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.toolkit.audit import ToolInvocationStore
from terminus.toolkit.catalog import load_catalog
from terminus.toolkit.context import (
    ReadContextDeniedError,
    ToolReadPolicyStore,
    TrustedReadContextFactory,
)
from terminus.toolkit.evidence import ToolEvidenceWriter, query_digest
from terminus.toolkit.evidence_tools import (
    EVIDENCE_TOOL_IDS,
    EvidenceReader,
    evidence_store_catalog,
)
from terminus.toolkit.gateway import ToolGateway
from terminus.toolkit.models import (
    EvidenceReference,
    Id,
    Provenance,
    ReadQuery,
    ToolExecutionContext,
    ToolResult,
)
from terminus.toolkit.registry import ExecutableToolRegistry, InstalledTool, ToolHandler
from terminus.toolkit.sources import EndpointResource, ReadCollection, ReadObservation
from terminus.toolkit.validation import ToolContractValidator
from terminus.toolkit.wazuh_readers import WazuhIndexerReader, WazuhManagerReader

_ID = TypeAdapter[str](Id)
_JSON = TypeAdapter[JsonValue](JsonValue)
_TOOLS = (
    "incident.get",
    "alerts.search",
    "identity.auth_events",
    "endpoint.agent",
    "collection.coverage",
    *EVIDENCE_TOOL_IDS,
)


@dataclass(frozen=True)
class _Batch:
    connector_id: str
    connector_version: str
    collection: ReadCollection


class InvestigationReadService:
    """One organization's explicit source bindings and read execution service."""

    def __init__(
        self,
        org_id: str,
        scheduler: SchedulerStore,
        policy_store: ToolReadPolicyStore,
        *,
        manager: WazuhManagerReader | None = None,
        indexer: WazuhIndexerReader | None = None,
    ) -> None:
        self.org_id: str = _ID.validate_python(org_id, strict=True)
        if scheduler.db is not policy_store.db:
            raise ValueError("Read services must share the canonical database")
        for reader, connector in (
            (manager, "wazuh_manager"),
            (indexer, "wazuh_indexer"),
        ):
            if reader is not None and (
                reader.settings.org_id != org_id
                or reader.settings.connector_id != connector
            ):
                raise ValueError(
                    "Connector belongs to a different organization or capability"
                )
        self.scheduler: SchedulerStore = scheduler
        self.manager: WazuhManagerReader | None = manager
        self.indexer: WazuhIndexerReader | None = indexer
        self.audit: ToolInvocationStore = ToolInvocationStore(
            scheduler.db, clock=scheduler.clock
        )
        self.validator: ToolContractValidator = ToolContractValidator(scheduler)
        self.writer: ToolEvidenceWriter = ToolEvidenceWriter(self.validator, self.audit)
        catalog = evidence_store_catalog(load_catalog())
        evidence_reader = EvidenceReader(self)
        configured = ["terminus_store"]
        if manager is not None:
            configured.append("wazuh_manager")
        if indexer is not None:
            configured.append("wazuh_indexer")
        descriptors = {item.tool_id: item for item in catalog.tools}
        self.registry: ExecutableToolRegistry = ExecutableToolRegistry(
            catalog,
            installed=tuple(
                InstalledTool(
                    descriptors[name],
                    evidence_reader.handler(name)
                    if name in EVIDENCE_TOOL_IDS
                    else self._handler(name),
                )
                for name in _TOOLS
            ),
            configured_connector_ids=configured,
        )
        self.contexts: TrustedReadContextFactory = TrustedReadContextFactory(
            scheduler, self.registry, policy_store, self.audit
        )
        self.gateway: ToolGateway = ToolGateway(
            self.registry,
            self.validator,
            self.audit,
            execution_authorizer=self.contexts.authorize,
        )

    def _handler(self, tool_id: str) -> ToolHandler:  # noqa: C901 - five fixed read routes
        async def read(context: ToolExecutionContext, query: ReadQuery) -> ToolResult:  # noqa: C901, PLR0911
            resource = self.contexts.resolve_resource(context, query.resource_id)
            if tool_id == "incident.get":
                if resource.kind != "incident" or query.event_kind not in {
                    "evidence",
                    "detection",
                }:
                    return self._gap(
                        tool_id, "unsupported", "incident_resource_required"
                    )
                return self._incident(context, query, tool_id)
            if resource.kind != "endpoint" or resource.agent_id is None:
                return self._gap(tool_id, "unsupported", "endpoint_resource_required")
            endpoint = EndpointResource(
                org_id=context.org_id,
                resource_id=resource.resource_id,
                agent_id=resource.agent_id,
            )
            if tool_id == "collection.coverage":
                if self.manager is None or self.indexer is None:
                    return self._gap(
                        tool_id, "unavailable", "coverage_sources_not_configured"
                    )
                if query.event_kind not in {"evidence", "coverage"}:
                    return self._gap(tool_id, "unsupported", "query_kind_not_supported")
                self.contexts.authorize(context)
                manager_result, indexer_result = await asyncio.gather(
                    self.manager.read(
                        query.model_copy(update={"event_kind": "coverage"}), endpoint
                    ),
                    self.indexer.read(
                        query.model_copy(update={"event_kind": "detection"}), endpoint
                    ),
                )
                return self._publish(
                    tool_id,
                    context,
                    query,
                    [
                        _Batch(
                            "wazuh_manager",
                            self.manager.settings.connector_version,
                            manager_result,
                        ),
                        _Batch(
                            "wazuh_indexer",
                            self.indexer.settings.connector_version,
                            indexer_result,
                        ),
                    ],
                )
            batches: list[_Batch] = []
            if tool_id == "endpoint.agent":
                if self.manager is None:
                    return self._gap(tool_id, "unavailable", "manager_not_configured")
                expected = "inventory"
                if query.event_kind not in {"evidence", expected}:
                    return self._gap(tool_id, "unsupported", "query_kind_not_supported")
                self.contexts.authorize(context)
                collection = await self.manager.read(
                    query.model_copy(update={"event_kind": expected}), endpoint
                )
                batches.append(
                    _Batch(
                        "wazuh_manager",
                        self.manager.settings.connector_version,
                        collection,
                    )
                )
            if tool_id in {"alerts.search", "identity.auth_events"}:
                if self.indexer is None:
                    return self._gap(tool_id, "unavailable", "indexer_not_configured")
                expected = (
                    "authentication"
                    if tool_id == "identity.auth_events"
                    else "detection"
                )
                if query.event_kind not in {"evidence", expected}:
                    return self._gap(tool_id, "unsupported", "query_kind_not_supported")
                self.contexts.authorize(context)
                collection = await self.indexer.read(
                    query.model_copy(update={"event_kind": expected}), endpoint
                )
                batches.append(
                    _Batch(
                        "wazuh_indexer",
                        self.indexer.settings.connector_version,
                        collection,
                    )
                )
            return self._publish(tool_id, context, query, batches)

        return read

    @staticmethod
    def _gap(
        tool_id: str,
        status: Literal["unavailable", "unsupported", "denied", "error"],
        code: str,
    ) -> ToolResult:
        return ToolResult(
            tool_id=tool_id, version="1.0", status=status, error_code=code, gaps=(code,)
        )

    def _incident(
        self, context: ToolExecutionContext, query: ReadQuery, tool_id: str
    ) -> ToolResult:
        # Fixed projection; include no configuration secrets, model verdicts or
        # synthesized summary as if they were raw source observations.
        with self.scheduler.db.transaction():
            self.contexts.authorize(context)
            row = self.scheduler.db.fetchone(
                "SELECT ticket_id, alert_id, org_id, raw_payload_json, created_at FROM incidents WHERE org_id=? AND ticket_id=?",
                (context.org_id, context.incident_id),
            )
            if row is None:
                return self._gap(tool_id, "unavailable", "incident_not_found")
            try:
                payload = _JSON.validate_json(
                    cast("str", row["raw_payload_json"]), strict=True
                )
                if not isinstance(payload, dict) or not payload:
                    return self._gap(
                        tool_id, "unavailable", "incident_source_payload_missing"
                    )
                if not payload.get("timestamp"):
                    return self._gap(
                        tool_id, "unavailable", "incident_source_timestamp_missing"
                    )
                stamp = datetime.fromisoformat(str(payload["timestamp"]))
                observation = ReadObservation(
                    source_id="terminus-incident",
                    source_event_id=cast("str", row["alert_id"]),
                    source_timestamp=stamp,
                    data={
                        "incident_id": context.incident_id,
                        "alert_id": cast("str", row["alert_id"]),
                        "raw_payload": payload,
                    },
                )
            except (TypeError, ValueError):
                return self._gap(tool_id, "error", "invalid_incident_source_payload")
            if not query.start <= observation.source_timestamp <= query.end:
                return self._gap(
                    tool_id, "unsupported", "incident_source_outside_window"
                )
            return self._publish(
                tool_id,
                context,
                query,
                [
                    _Batch(
                        "terminus_store",
                        "1.0",
                        ReadCollection(
                            status="ok",
                            observations=(observation,),
                            coverage="complete",
                        ),
                    )
                ],
            )

    def _publish(
        self,
        tool_id: str,
        context: ToolExecutionContext,
        query: ReadQuery,
        batches: list[_Batch],
    ) -> ToolResult:
        with self.scheduler.db.transaction():
            try:
                self.contexts.authorize(context)
            except ReadContextDeniedError:
                return self._gap(tool_id, "denied", "read_authorization_changed")
            return self._publish_owned(tool_id, context, query, batches)

    def _publish_owned(  # noqa: C901 - bounded conservative result assembly
        self,
        tool_id: str,
        context: ToolExecutionContext,
        query: ReadQuery,
        batches: list[_Batch],
    ) -> ToolResult:
        failures = [
            batch
            for batch in batches
            if batch.collection.status in {"unavailable", "unsupported", "error"}
        ]
        if failures and len(failures) == len(batches):
            return self._gap(
                tool_id,
                cast(
                    "Literal['unavailable', 'unsupported', 'error']",
                    failures[0].collection.status,
                ),
                "source_collection_unavailable",
            )
        gaps = tuple(gap for batch in batches for gap in batch.collection.gaps)
        partial = bool(
            failures or gaps or any(b.collection.status == "partial" for b in batches)
        )
        truncated = any(b.collection.truncated for b in batches)
        # Each source batch produces one immutable envelope. The combined data
        # and provenance need headroom below the gateway's 64 KiB result bound.
        prepared: list[tuple[_Batch, tuple[ReadObservation, ...]]] = []
        per_source_bytes = 45000 // max(len(batches), 1)
        for batch in batches:
            if batch in failures:
                continue
            observations = batch.collection.observations
            while (
                observations
                and len(
                    json.dumps(
                        {
                            "observed": [o.data for o in observations],
                            "event_ids": [o.source_event_id for o in observations],
                        },
                        allow_nan=False,
                    ).encode()
                )
                > per_source_bytes
            ):
                observations = observations[:-1]
                partial = truncated = True
            if len(observations) != len(batch.collection.observations):
                gaps += ("Model-facing evidence/output bound reached",)
            prepared.append((batch, observations))
        evidence: list[EvidenceReference] = []
        provenance: list[Provenance] = []
        empty_traces: list[Provenance] = []
        data: list[JsonValue] = []
        descriptor = self.registry.descriptor(tool_id)
        for batch, observations in prepared:
            if not observations:
                if batch.collection.status in {"ok", "empty", "partial"}:
                    empty_traces.append(
                        Provenance(
                            source_id=f"{batch.connector_id}.query",
                            connector_id=batch.connector_id,
                            connector_version=batch.connector_version,
                            source_event_ids=(),
                            source_timestamp=query.end,
                            collected_at=self.audit.clock(),
                            query_digest=query_digest(query),
                        )
                    )
                continue
            observed: JsonValue = [o.data for o in observations]
            ref, trace = self.writer.record(
                descriptor,
                context,
                query,
                connector_id=batch.connector_id,
                connector_version=batch.connector_version,
                source_id=observations[0].source_id,
                source_timestamp=max(o.source_timestamp for o in observations),
                source_event_ids=tuple(o.source_event_id for o in observations),
                content=observed,
            )
            evidence.append(ref)
            provenance.append(trace)
            data.append(observed)
        if evidence and empty_traces:
            partial = True
            gaps += tuple(
                f"{trace.connector_id} supplied no usable observations"
                for trace in empty_traces
            )
        elif not evidence:
            provenance.extend(empty_traces)
        if tool_id == "collection.coverage":
            # Alert silence cannot establish healthy collection, absence of
            # tampering or endpoint protection, even when both reads succeeded.
            partial = True
            gaps += (
                "Connection and alert observations do not establish collection completeness, tampering status or host health",
            )
        if not evidence and partial and not gaps:
            gaps = ("No usable observations collected",)
        return ToolResult(
            tool_id=tool_id,
            version="1.0",
            status="partial" if partial else ("ok" if evidence else "empty"),
            data=data[0] if len(data) == 1 else (data or None),
            evidence=tuple(evidence),
            provenance=tuple(provenance),
            coverage="incomplete" if partial else "complete",
            truncated=truncated,
            gaps=tuple(dict.fromkeys(gaps)),
        )

    async def execute(
        self,
        lease: JobLease,
        actor_user_id: str,
        tool_id: str,
        arguments: ReadQuery | dict[str, object] | str,
    ) -> ToolResult:
        """Trusted caller supplies actor/lease separately from model arguments."""
        try:
            tool_id = _ID.validate_python(tool_id, strict=True)
        except ValueError:
            return self._gap("invalid-tool", "unsupported", "invalid_tool_id")
        if lease.org_id != self.org_id:
            return self._gap(tool_id, "denied", "foreign_organization")
        try:
            context = self.contexts.build(lease, actor_user_id)
            self.contexts.authorize(context)
        except (ValueError, LookupError):
            return self._gap(tool_id, "denied", "read_context_denied")
        return await self.gateway.execute(tool_id, arguments, context=context)
