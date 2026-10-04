"""Read-only incident evidence tools over durable orchestration records.

`evidence.get`, `evidence.timeline` and `evidence.validate_citations` read only
the canonical evidence table through the trusted, incident-scoped context. They
make no network call, no model call and cause no dispatch effect.

`ReadQuery` cannot carry evidence identifiers (strict, extra fields forbidden,
and its resource must be an operator-bound incident resource). Identifiers
therefore arrive through `cited_evidence_ids`, which only trusted server code
(the specialist runtime parsing model output) can open around
`InvestigationReadService.execute`. A foreign-incident, foreign-tenant, missing
or malformed identifier is reported identically so existence never leaks.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from typing import TYPE_CHECKING, Literal, Protocol, cast

from pydantic import JsonValue, TypeAdapter, ValidationError

from terminus.orchestration.models import EvidenceRecord
from terminus.orchestration.storage import OrchestrationNotFoundError
from terminus.toolkit.catalog import ToolkitCatalog
from terminus.toolkit.context import ReadContextDeniedError
from terminus.toolkit.evidence import query_digest
from terminus.toolkit.models import (
    Id,
    Provenance,
    ReadQuery,
    ToolExecutionContext,
    ToolResult,
)
from terminus.toolkit.registry import ToolHandler

if TYPE_CHECKING:
    from terminus.orchestration.scheduler_store import SchedulerStore
    from terminus.toolkit.audit import ToolInvocationStore
    from terminus.toolkit.context import TrustedReadContextFactory
    from terminus.toolkit.evidence import ToolEvidenceWriter
    from terminus.toolkit.registry import ExecutableToolRegistry

EVIDENCE_TOOL_IDS = ("evidence.get", "evidence.timeline", "evidence.validate_citations")
MAX_CITATIONS = 50
_CONNECTOR = "terminus_store"
_SOURCE = "terminus-evidence"
_OUTPUT_BUDGET = 45000
_ID = TypeAdapter[str](Id)
_CITED: ContextVar[tuple[str, ...]] = ContextVar("terminus_cited_evidence_ids")


@contextmanager
def cited_evidence_ids(ids: tuple[str, ...] | list[str]) -> Generator[None]:
    """Trusted callers open this around `execute` to name the cited IDs."""
    token = _CITED.set(tuple(ids))
    try:
        yield
    finally:
        _CITED.reset(token)


def evidence_store_catalog(catalog: ToolkitCatalog) -> ToolkitCatalog:
    """Bind the three evidence tools to the `terminus_store` connector.

    Tool provenance must name a connector declared by the descriptor, and the
    packaged JSON declares none for these tools, so results could not carry
    provenance. The derived catalog is revalidated by the unmodified catalog
    validator; the packaged fragments and their checks are untouched.
    """
    data = cast("dict[str, list[dict[str, object]]]", catalog.model_dump())
    for tool in data["tools"]:
        if tool["tool_id"] in EVIDENCE_TOOL_IDS:
            tool["connector_ids"] = (_CONNECTOR,)
    for connector in data["connectors"]:
        if connector["connector_id"] == _CONNECTOR:
            capabilities = cast("tuple[str, ...]", connector["capabilities"])
            connector["capabilities"] = (
                *capabilities,
                *(name for name in EVIDENCE_TOOL_IDS if name not in capabilities),
            )
    return ToolkitCatalog.model_validate(data)


class EvidenceToolHost(Protocol):
    scheduler: SchedulerStore
    contexts: TrustedReadContextFactory
    writer: ToolEvidenceWriter
    audit: ToolInvocationStore
    registry: ExecutableToolRegistry


def _gap(
    tool_id: str,
    status: Literal["unavailable", "unsupported", "denied", "error"],
    code: str,
) -> ToolResult:
    return ToolResult(
        tool_id=tool_id, version="1.0", status=status, error_code=code, gaps=(code,)
    )


def _size(value: object) -> int:
    return len(json.dumps(value, allow_nan=False, default=str).encode())


class EvidenceReader:
    """Handlers for the evidence tools, bound to one read service."""

    def __init__(self, host: EvidenceToolHost) -> None:
        self.host: EvidenceToolHost = host

    def handler(self, tool_id: str) -> ToolHandler:
        async def read(context: ToolExecutionContext, query: ReadQuery) -> ToolResult:
            return self._read(tool_id, context, query)

        return read

    # -- shared helpers -------------------------------------------------

    def _lookup(
        self, context: ToolExecutionContext, evidence_id: str
    ) -> EvidenceRecord | None:
        """Foreign tenant, foreign incident, missing and malformed look alike."""
        try:
            record = self.host.scheduler.records.get_evidence(
                context.org_id, _ID.validate_python(evidence_id, strict=True)
            )
        except (OrchestrationNotFoundError, ValidationError, ValueError):
            return None
        if (record.org_id, record.incident_id) != (context.org_id, context.incident_id):
            return None
        return record

    @staticmethod
    def _metadata(record: EvidenceRecord) -> dict[str, JsonValue]:
        return {
            "evidence_id": record.evidence_id,
            "task_id": record.task_id,
            "source": record.source,
            "source_timestamp": record.source_timestamp.isoformat(),
            "collected_at": record.collected_at.isoformat(),
            "content_hash": record.content_hash,
            "has_content_ref": record.content_ref is not None,
            "content_bytes": _size(record.content) if record.content is not None else 0,
        }

    def _trace(
        self, query: ReadQuery, stamp: datetime, event_ids: tuple[str, ...]
    ) -> Provenance:
        return Provenance(
            source_id=_SOURCE,
            connector_id=_CONNECTOR,
            connector_version="1.0",
            source_event_ids=event_ids,
            source_timestamp=stamp,
            collected_at=self.host.audit.clock(),
            query_digest=query_digest(query),
        )

    def _publish(
        self,
        tool_id: str,
        context: ToolExecutionContext,
        query: ReadQuery,
        *,
        observed: JsonValue,
        stamp: datetime,
        event_ids: tuple[str, ...],
        partial: bool,
        truncated: bool,
        gaps: tuple[str, ...],
    ) -> ToolResult:
        ref, trace = self.host.writer.record(
            self.host.registry.descriptor(tool_id),
            context,
            query,
            connector_id=_CONNECTOR,
            connector_version="1.0",
            source_id=_SOURCE,
            source_timestamp=stamp,
            source_event_ids=event_ids,
            content=observed,
        )
        return ToolResult(
            tool_id=tool_id,
            version="1.0",
            status="partial" if partial else "ok",
            data=observed,
            evidence=(ref,),
            provenance=(trace,),
            coverage="incomplete" if partial else "complete",
            truncated=truncated,
            gaps=tuple(dict.fromkeys(gaps)),
        )

    def _no_data(
        self,
        tool_id: str,
        query: ReadQuery,
        gaps: tuple[str, ...],
        *,
        truncated: bool,
    ) -> ToolResult:
        # Missing telemetry is a disclosed gap, never an empty success.
        return ToolResult(
            tool_id=tool_id,
            version="1.0",
            status="partial",
            provenance=(self._trace(query, query.end, ()),),
            coverage="incomplete",
            truncated=truncated,
            gaps=gaps,
        )

    # -- dispatch -------------------------------------------------------

    def _read(  # noqa: PLR0911 - fixed fail-closed admission exits
        self, tool_id: str, context: ToolExecutionContext, query: ReadQuery
    ) -> ToolResult:
        try:
            resource = self.host.contexts.resolve_resource(context, query.resource_id)
        except ReadContextDeniedError:
            return _gap(tool_id, "denied", "read_authorization_changed")
        if resource.kind != "incident":
            return _gap(tool_id, "unsupported", "incident_resource_required")
        if query.event_kind != "evidence":
            return _gap(tool_id, "unsupported", "query_kind_not_supported")
        cited = _CITED.get(())
        try:
            with self.host.scheduler.db.transaction():
                self.host.contexts.authorize(context)
                if tool_id == "evidence.get":
                    return self._get(tool_id, context, query, cited)
                if tool_id == "evidence.timeline":
                    return self._timeline(tool_id, context, query)
                return self._validate(tool_id, context, query, cited)
        except ReadContextDeniedError:
            return _gap(tool_id, "denied", "read_authorization_changed")

    def _get(
        self,
        tool_id: str,
        context: ToolExecutionContext,
        query: ReadQuery,
        cited: tuple[str, ...],
    ) -> ToolResult:
        if len(cited) != 1:
            return _gap(tool_id, "unsupported", "single_evidence_id_required")
        record = self._lookup(context, cited[0])
        if record is None:
            return _gap(tool_id, "unavailable", "evidence_not_found")
        if not query.start <= record.source_timestamp <= query.end:
            return _gap(tool_id, "unsupported", "evidence_outside_query_window")
        return self._publish(
            tool_id,
            context,
            query,
            observed=[self._metadata(record)],
            stamp=record.source_timestamp,
            event_ids=(record.evidence_id,),
            partial=False,
            truncated=False,
            gaps=(),
        )

    def _timeline(
        self, tool_id: str, context: ToolExecutionContext, query: ReadQuery
    ) -> ToolResult:
        cap = query.page_size * query.max_pages
        scanned: list[EvidenceRecord] = []
        offset = 0
        while len(scanned) <= cap:
            page = self.host.scheduler.records.list_evidence(
                context.org_id,
                incident_id=context.incident_id,
                limit=min(200, cap + 1 - len(scanned)),
                offset=offset,
            )
            scanned.extend(page)
            offset += len(page)
            if not page:
                break
        truncated = len(scanned) > cap
        scanned = scanned[:cap]
        gaps: list[str] = []
        if truncated:
            gaps.append("Evidence scan bound reached; older or later records omitted")
        matching = sorted(
            (
                record
                for record in scanned
                if query.start <= record.source_timestamp <= query.end
                and not self._is_evidence_tool_output(record)
            ),
            key=lambda item: (item.source_timestamp, item.evidence_id),
        )
        if not matching:
            gaps.append("No incident evidence recorded within the query window")
            return self._no_data(tool_id, query, tuple(gaps), truncated=truncated)
        entries = [self._metadata(item) for item in matching]
        while entries and _size(entries) > _OUTPUT_BUDGET:
            _ = entries.pop()
            truncated = True
        if len(entries) != len(matching):
            gaps.append("Model-facing evidence/output bound reached")
        return self._publish(
            tool_id,
            context,
            query,
            observed=cast("JsonValue", entries),
            stamp=max(item.source_timestamp for item in matching[: len(entries)]),
            event_ids=tuple(item.evidence_id for item in matching[: len(entries)]),
            partial=truncated,
            truncated=truncated,
            gaps=tuple(gaps),
        )

    @staticmethod
    def _is_evidence_tool_output(record: EvidenceRecord) -> bool:
        content = record.content
        return isinstance(content, dict) and content.get("tool_id") in EVIDENCE_TOOL_IDS

    def _validate(
        self,
        tool_id: str,
        context: ToolExecutionContext,
        query: ReadQuery,
        cited: tuple[str, ...],
    ) -> ToolResult:
        if not cited:
            return _gap(tool_id, "unsupported", "citation_ids_required")
        if len(cited) > MAX_CITATIONS:
            return _gap(tool_id, "unsupported", "too_many_citations")
        results: list[JsonValue] = []
        valid_ids: list[str] = []
        seen: set[str] = set()
        for index, evidence_id in enumerate(cited):
            if evidence_id in seen:
                continue
            seen.add(evidence_id)
            record = self._lookup(context, evidence_id)
            shown = evidence_id if _is_id(evidence_id) else f"invalid-citation-{index}"
            if record is None:
                results.append({"evidence_id": shown, "status": "not_found"})
                continue
            valid_ids.append(record.evidence_id)
            results.append(
                {
                    "evidence_id": record.evidence_id,
                    "status": "valid",
                    "source": record.source,
                    "source_timestamp": record.source_timestamp.isoformat(),
                    "content_hash": record.content_hash,
                }
            )
        unresolved = len(results) - len(valid_ids)
        gaps: tuple[str, ...] = ()
        if unresolved:
            gaps = (
                f"{unresolved} citation(s) could not be resolved within this incident",
            )
        observed: JsonValue = {
            "citations": results,
            "claim_support": "not_verified",
            "note": "Citation existence does not prove the associated claim",
        }
        return self._publish(
            tool_id,
            context,
            query,
            observed=observed,
            stamp=query.end,
            event_ids=tuple(valid_ids),
            partial=bool(unresolved),
            truncated=False,
            gaps=gaps,
        )


def _is_id(value: str) -> bool:
    try:
        _ = _ID.validate_python(value, strict=True)
    except ValidationError:
        return False
    return True


__all__ = [
    "EVIDENCE_TOOL_IDS",
    "MAX_CITATIONS",
    "EvidenceReader",
    "cited_evidence_ids",
    "evidence_store_catalog",
]
