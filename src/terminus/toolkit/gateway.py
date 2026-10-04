"""Internal, explicitly installed read-tool execution with durable admission.

This gateway is deliberately not exposed to model arguments or HTTP callers.
Trusted server code supplies the execution context and installs async handlers.
No live adapters, credentials, dynamic imports or effect dispatch are installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Literal

from pydantic import TypeAdapter, ValidationError

from terminus.orchestration.scheduler_store import SchedulerLeaseError
from terminus.toolkit.audit import (
    InvocationReservation,
    ToolAuditError,
    ToolInvocationStore,
    canonical_query_digest,
)
from terminus.toolkit.models import (
    Id,
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
    ToolResult,
)
from terminus.toolkit.registry import ExecutableToolRegistry, ToolRegistryError
from terminus.toolkit.validation import ToolContractValidator

FailureStatus = Literal["unavailable", "unsupported", "denied", "error"]
_TOOL_ID = TypeAdapter[str](Id)


def _failure(tool_id: str, status: FailureStatus, code: str) -> ToolResult:
    return ToolResult(
        tool_id=tool_id,
        version="1.0",
        status=status,
        error_code=code,
    )


def _parse_query(arguments: object) -> ReadQuery:
    if isinstance(arguments, ReadQuery):
        return ReadQuery.model_validate(arguments.model_dump())
    if isinstance(arguments, str):
        return ReadQuery.model_validate_json(arguments)
    if isinstance(arguments, dict):
        # JSON admits ISO timestamps without weakening strict numeric/extra checks.
        try:
            payload = json.dumps(arguments, allow_nan=False)
        except (TypeError, ValueError):
            return ReadQuery.model_validate(arguments)
        return ReadQuery.model_validate_json(payload)
    raise TypeError("Arguments must be a strict read query")


def _bounded_arguments_digest(  # noqa: PLR0911 - bounded fail-closed encoding exits
    arguments: ReadQuery | dict[str, object] | str,
) -> tuple[str, str | None]:
    """Stop encoding at the input limit, before hashing or parsing a large call."""
    rejected = hashlib.sha256(b"rejected-arguments").hexdigest()
    if isinstance(arguments, str):
        if len(arguments) > 65536:
            return rejected, "arguments_too_large"
        encoded = arguments.encode()
        if len(encoded) > 65536:
            return rejected, "arguments_too_large"
        return hashlib.sha256(encoded).hexdigest(), None
    payload = (
        arguments.model_dump(mode="json")
        if isinstance(arguments, ReadQuery)
        else arguments
    )
    digest = hashlib.sha256()
    encoded_size = 0
    try:
        encoder = json.JSONEncoder(sort_keys=True, default=str, allow_nan=False)
        for chunk in encoder.iterencode(payload):
            if len(chunk) > 65536:
                return rejected, "arguments_too_large"
            encoded = chunk.encode()
            encoded_size += len(encoded)
            if encoded_size > 65536:
                return rejected, "arguments_too_large"
            digest.update(encoded)
    except (TypeError, ValueError, RecursionError):
        return rejected, "invalid_arguments"
    return digest.hexdigest(), None


def _observe_detached(task: asyncio.Future[ToolResult]) -> None:
    # Cancellation can be suppressed by a handler. Its eventual result is discarded.
    if not task.cancelled():
        _ = task.exception()


def _trusted_context(context: object) -> ToolExecutionContext:
    if not isinstance(context, ToolExecutionContext):
        raise TypeError("Execution context must be server-created")
    return ToolExecutionContext.model_validate(context.model_dump())


class ToolGateway:
    """Admit, reserve, bound and fence one internal read-only invocation."""

    def __init__(
        self,
        registry: ExecutableToolRegistry,
        validator: ToolContractValidator,
        audit: ToolInvocationStore,
    ) -> None:
        if validator.scheduler.db is not audit.db:
            raise ValueError("Validation and audit must use the same database")
        self.registry: ExecutableToolRegistry = registry
        self.validator: ToolContractValidator = validator
        self.audit: ToolInvocationStore = audit

    def _deny(
        self,
        context: ToolExecutionContext,
        tool_id: str,
        digest: str,
        status: FailureStatus,
        code: str,
    ) -> ToolResult:
        try:
            _ = self.audit.record_denial(context, tool_id, digest, code)
        except ToolAuditError as exc:
            if exc.code == "denial_quota_exhausted":
                return _failure(tool_id, "denied", exc.code)
            return _failure(tool_id, "unavailable", "audit_unavailable")
        except Exception:
            return _failure(tool_id, "unavailable", "audit_unavailable")
        return _failure(tool_id, status, code)

    def _finish(
        self,
        reservation: InvocationReservation,
        context: ToolExecutionContext,
        result: ToolResult,
        *,
        uncertain: bool = False,
    ) -> ToolResult:
        try:
            invocation = self.audit.finish(
                reservation,
                context,
                result,
                uncertain=uncertain,
            )
        except Exception:
            # A reservation is already durably unknown; no unaudited data escapes.
            return _failure(result.tool_id, "unavailable", "audit_unavailable")
        if invocation.outcome == "unknown":
            return _failure(result.tool_id, "error", "execution_unknown")
        return result

    def _validate_output(
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
        result: object,
        reservation: InvocationReservation,
    ) -> ToolResult:
        if not isinstance(result, ToolResult):
            raise TypeError("Handler must return a strict ToolResult")
        result = ToolResult.model_validate(result.model_dump())
        self.validator.validate_result(descriptor, context, result)
        digest = canonical_query_digest(query)
        if any(item.query_digest != digest for item in result.provenance):
            raise ValueError("Provenance must identify the admitted query")
        if any(
            not query.start <= item.source_timestamp <= query.end
            or len(item.source_event_ids) > query.page_size * query.max_pages
            or item.collected_at < reservation.timestamp
            for item in result.provenance
        ):
            raise ValueError("Provenance exceeds admitted time or page bounds")
        if result.status in {"ok", "empty"} and not result.provenance:
            raise ValueError("Successful collection requires provenance")
        if result.status in {"unavailable", "unsupported", "denied", "error"} and (
            result.evidence or result.provenance
        ):
            raise ValueError("Failure must not present evidence as collected findings")
        if descriptor.effect == "read":
            self._validate_read_evidence(
                descriptor, context, query, result, reservation
            )
        return result

    def _validate_read_evidence(  # noqa: C901 - source identity and observation binding
        self,
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
        result: ToolResult,
        reservation: InvocationReservation,
    ) -> None:
        observed_provenance: list[object] = []
        observations: list[object] = []
        if result.status == "ok" and (
            not result.evidence or result.data in (None, [], {}, "")
        ):
            raise ValueError("Successful reads require observed evidence and data")
        if result.status == "empty" and result.evidence:
            raise ValueError("Empty reads cannot contain observed events")
        if (
            result.status == "partial"
            and not result.evidence
            and (result.data is not None or not result.gaps or not result.provenance)
        ):
            raise ValueError("Partial reads without observations need explicit gaps")
        for reference in result.evidence:
            record = self.validator.records.get_evidence(
                context.org_id,
                reference.evidence_id,
            )
            content = record.content
            if not isinstance(content, dict) or any(
                content.get(name) != value
                for name, value in {
                    "tool_id": descriptor.tool_id,
                    "tool_version": descriptor.version,
                    "invocation_id": reservation.invocation_id,
                    "run_id": context.run_id,
                    "resource_id": query.resource_id,
                }.items()
            ):
                raise ValueError("Read evidence must belong to this invocation")
            if "observed" not in content or content["observed"] is None:
                raise ValueError("Read evidence must contain observed data")
            provenance = content.get("provenance")
            if record.task_id != context.task_id or not any(
                item.model_dump(mode="json") == provenance
                and record.source == item.source_id
                and record.source_timestamp == item.source_timestamp
                for item in result.provenance
            ):
                raise ValueError("Read evidence must bind its source provenance")
            observed_provenance.append(provenance)
            observations.append(content["observed"])
        if observations:
            expected_data = observations[0] if len(observations) == 1 else observations
            if json.dumps(result.data, sort_keys=True, allow_nan=False) != json.dumps(
                expected_data,
                sort_keys=True,
                allow_nan=False,
            ):
                raise ValueError("Read data must equal its persisted observations")
        if result.evidence and any(
            item.model_dump(mode="json") not in observed_provenance
            for item in result.provenance
        ):
            raise ValueError("Result provenance must be backed by read evidence")

    async def _wait_handler(
        self,
        task: asyncio.Future[ToolResult],
        descriptor: ToolDescriptor,
        context: ToolExecutionContext,
        query: ReadQuery,
    ) -> Literal["complete", "deadline_exceeded", "ownership_lost"]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + min(descriptor.limits.timeout_seconds, 10)
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return "deadline_exceeded"
            completed, _ = await asyncio.wait({task}, timeout=min(remaining, 0.1))
            if completed:
                return "complete"
            try:
                self.validator.validate_request(descriptor, context, query)
            except Exception:
                return "ownership_lost"

    async def execute(  # noqa: C901, PLR0911, PLR0912
        self,
        tool_id: str,
        arguments: ReadQuery | dict[str, object] | str,
        *,
        context: ToolExecutionContext,
    ) -> ToolResult:
        """Execute with trusted context; scope can never arrive inside arguments."""
        # Revalidate frozen models because model_copy(update=...) skips validation.
        context = _trusted_context(context)
        digest, argument_error = _bounded_arguments_digest(arguments)
        try:
            tool_id = _TOOL_ID.validate_python(tool_id, strict=True)
        except ValidationError:
            return self._deny(
                context,
                "invalid-tool",
                digest,
                "unsupported",
                "invalid_tool_id",
            )
        if argument_error:
            return self._deny(context, tool_id, digest, "denied", argument_error)
        try:
            query = _parse_query(arguments)
        except (ValidationError, TypeError, ValueError):
            return self._deny(
                context,
                tool_id,
                digest,
                "denied",
                "invalid_arguments",
            )
        try:
            installed = self.registry.resolve(tool_id, context.role)
        except ToolRegistryError as exc:
            return self._deny(context, tool_id, digest, exc.status, exc.error_code)
        descriptor = installed.descriptor
        try:
            self.validator.validate_request(descriptor, context, query)
        except (ValueError, SchedulerLeaseError):
            return self._deny(context, tool_id, digest, "denied", "request_denied")
        try:
            reservation = self.audit.reserve(descriptor, context, query)
        except ToolAuditError as exc:
            return self._deny(context, tool_id, digest, "denied", exc.code)
        except Exception:
            return _failure(tool_id, "unavailable", "audit_unavailable")

        # Reservation is durable before the handler coroutine can perform I/O.
        handler_context = context.model_copy(
            update={"invocation_id": reservation.invocation_id},
        )
        task = asyncio.ensure_future(installed.handler(handler_context, query))
        try:
            wait_outcome = await self._wait_handler(task, descriptor, context, query)
            if wait_outcome != "complete":
                _ = task.cancel()
                task.add_done_callback(_observe_detached)
                return self._finish(
                    reservation,
                    context,
                    _failure(tool_id, "error", wait_outcome),
                    uncertain=True,
                )
            try:
                result = task.result()
            except asyncio.CancelledError:
                return self._finish(
                    reservation,
                    context,
                    _failure(tool_id, "error", "handler_cancelled"),
                    uncertain=True,
                )
            except TimeoutError:
                return self._finish(
                    reservation,
                    context,
                    _failure(tool_id, "error", "handler_timeout"),
                    uncertain=True,
                )
            except Exception:
                result = _failure(tool_id, "error", "handler_failed")
            try:
                self.validator.validate_request(descriptor, context, query)
            except Exception:
                return self._finish(
                    reservation,
                    context,
                    _failure(tool_id, "error", "ownership_lost"),
                    uncertain=True,
                )
            try:
                result = self._validate_output(
                    descriptor,
                    context,
                    query,
                    result,
                    reservation,
                )
            except Exception:
                result = _failure(tool_id, "error", "invalid_result")
            return self._finish(reservation, context, result)
        except asyncio.CancelledError:
            _ = task.cancel()
            task.add_done_callback(_observe_detached)
            _ = self._finish(
                reservation,
                context,
                _failure(tool_id, "error", "execution_cancelled"),
                uncertain=True,
            )
            raise
