"""Common specialist handler: fixed ordered read plan plus optional cited model step.

Authority comes only from the scheduler lease: organization and role are read
from the leased task, the plan is fixed code, every read goes through the
ToolGateway with a freshly built trusted context, and the model (when routed)
can neither choose tools nor scope. Gaps are explicit; a run with gaps is not a
security verdict and tool absence never becomes a finding.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import cast

from pydantic import JsonValue, ValidationError

from terminus.model_gateway.routing import (
    ClientFactory,
    ModelRoutingDeniedError,
    ModelRoutingService,
)
from terminus.orchestration.models import Task
from terminus.orchestration.scheduler import JobContext, JobHandler, JobLeaseLostError
from terminus.orchestration.specialists.models import (
    Finding,
    GapCode,
    ModelFindings,
    ModelRef,
    SpecialistGap,
    SpecialistResult,
    ToolCallRecord,
)
from terminus.orchestration.specialists.prompts import FINDING_OUTPUT_SCHEMA
from terminus.toolkit.context import ReadContextDeniedError
from terminus.toolkit.evidence_tools import MAX_CITATIONS, cited_evidence_ids
from terminus.toolkit.models import ReadQuery, ToolResult
from terminus.toolkit.readers import InvestigationReadService

_LOGGER = logging.getLogger(__name__)
MAX_TOOL_CALLS = 20
MAX_MODEL_EVIDENCE = 16  # admission.prepare accepts at most 16 evidence ids
MAX_EVIDENCE_IDS = 60
MAX_FINDINGS = 8
MAX_GAPS = 30


@dataclass(frozen=True)
class QueryContext:
    """Trusted facts for query builders; never derived from model output.

    ``incident_time`` is the source timestamp of the durable incident record
    (None when unknown, in which case builders anchor on claim time).
    """

    incident_time: datetime | None = None
    authentication_incident: bool = False


QueryBuilder = Callable[[Task, QueryContext], ReadQuery]
ReadServiceResolver = Callable[[str], InvestigationReadService | None]
# (org_id, incident_id) -> incident source timestamp from the durable record.
IncidentTimeResolver = Callable[[str, str], datetime | None]


@dataclass(frozen=True)
class SharedHelpContext:
    """Server-derived evidence contract for one admitted delegated task."""

    help_request_id: str
    objective: str
    expected_evidence_kinds: tuple[str, ...]
    shared_evidence_ids: tuple[str, ...]


HelpContextResolver = Callable[[str, str], SharedHelpContext | None]


@dataclass(frozen=True)
class PlannedCall:
    """One fixed step: a catalog tool id and a builder for its trusted query."""

    tool_id: str
    build_query: QueryBuilder
    # evidence.* tools: cite only ids collected earlier in THIS run (never model output).
    cite_run_evidence: bool = False


@dataclass(frozen=True)
class RoleSpec:
    role: str
    plan: tuple[PlannedCall, ...]


@dataclass(frozen=True)
class SpecialistDeps:
    read_service_for: ReadServiceResolver
    actor_user_id: str
    routing: ModelRoutingService | None = None
    client_for: ClientFactory | None = None
    incident_time_for: IncidentTimeResolver | None = None
    help_context_for: HelpContextResolver | None = None
    authentication_incident_for: Callable[[str, str], bool] | None = None


def _gap(code: GapCode, tool_id: str | None = None, detail: str = "") -> SpecialistGap:
    return SpecialistGap(code=code, tool_id=tool_id, detail=detail[:200])


def _classify(result: ToolResult) -> list[SpecialistGap]:
    tool = result.tool_id[:200]
    detail = (result.error_code or "; ".join(result.gaps) or result.status)[:200]
    if result.status == "denied":
        return [_gap("denied", tool, detail)]
    if result.status in {"unavailable", "unsupported", "error"}:
        if result.error_code in {"tool_not_installed", "tool_not_supported"}:
            return [_gap("tool_not_installed", tool, detail)]
        return [_gap("tool_unavailable", tool, detail)]
    if (
        result.status == "partial"
        or result.truncated
        or result.coverage == "incomplete"
        or result.gaps
    ):
        return [_gap("coverage_partial", tool, detail)]
    return []


def _incident_time(
    deps: SpecialistDeps, org_id: str, incident_id: str
) -> datetime | None:
    if deps.incident_time_for is None:
        return None
    try:
        stamp = deps.incident_time_for(org_id, incident_id)
    except Exception:
        _LOGGER.warning("incident time lookup failed", exc_info=True)
        return None
    if stamp is None or stamp.tzinfo is None or stamp.utcoffset() is None:
        return None
    return stamp


def _finalize(  # noqa: C901
    role: str,
    calls: list[ToolCallRecord],
    evidence: list[str],
    findings: list[Finding],
    gaps: list[SpecialistGap],
    model: ModelRef | None,
    *,
    error: bool = False,
) -> SpecialistResult:
    out_gaps = list(dict.fromkeys(gaps))
    ids = list(dict.fromkeys(evidence))
    if len(ids) > MAX_EVIDENCE_IDS:
        ids = ids[:MAX_EVIDENCE_IDS]
        out_gaps.append(_gap("result_truncated", None, "evidence ids capped"))
    out_gaps = out_gaps[:MAX_GAPS]
    kept = findings[:MAX_FINDINGS]
    while True:
        if error:
            status = "error"
        elif not ids and not kept:
            status = "insufficient_telemetry"
        elif out_gaps:
            status = "partial"
        else:
            status = "completed"
        try:
            return SpecialistResult(
                status=status,
                role=role,
                tool_calls=tuple(calls),
                evidence_ids=tuple(ids),
                findings=tuple(kept),
                gaps=tuple(out_gaps),
                model=model,
                execution_mode="tools_and_model" if model else "tools_only",
            )
        except ValidationError:
            # Bounded fallback: shed the least important material until it fits.
            if len(kept) > 1:
                kept = kept[:-1]
            elif len(ids) > 10:
                ids = ids[: len(ids) // 2]
            elif len(out_gaps) > 1:
                out_gaps = out_gaps[:-1]
            elif out_gaps and out_gaps[0].detail:
                out_gaps = [SpecialistGap(code=out_gaps[0].code)]
            else:
                kept, ids, calls, model = [], [], calls[:1], None


async def _model_step(
    ctx: JobContext,
    deps: SpecialistDeps,
    evidence: list[str],
    gaps: list[SpecialistGap],
) -> tuple[list[Finding], ModelRef | None]:
    routing, client_for = deps.routing, deps.client_for
    if routing is None or client_for is None or not evidence:
        return [], None
    await ctx.checkpoint()
    sent = tuple(evidence[:MAX_MODEL_EVIDENCE])
    if len(evidence) > len(sent):
        gaps.append(_gap("coverage_partial", None, "model saw first 16 evidence ids"))
    try:
        routed = await routing.route_fixture(
            ctx.lease,
            deps.actor_user_id,
            sent,
            client_for,
            output_schema=FINDING_OUTPUT_SCHEMA,
        )
    except ModelRoutingDeniedError:
        await ctx.checkpoint()
        gaps.append(_gap("model_unavailable", None, "routing denied"))
        return [], None
    except JobLeaseLostError:
        raise
    except Exception:
        # Routing owns reservation settlement, including ambiguous failures.
        # Preserve collected evidence without retrying a potentially paid call.
        # Never copy provider errors (which may contain credentials) into results.
        await ctx.checkpoint()
        _LOGGER.warning("specialist model route failed")
        gaps.append(_gap("model_unavailable", None, "model route failed"))
        return [], None
    response = routed.response
    ref = ModelRef(
        connection_id=routed.selected.connection_id,
        model=routed.selected.model,
        route_id=routed.route_id,
        reservation_id=routed.selected.reservation_id,
        usage=(
            response.usage
            if any(
                value is not None
                for value in (
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                    response.usage.total_tokens,
                    response.usage.cached_input_tokens,
                    response.usage.reasoning_tokens,
                )
            )
            else None
        ),
        cost_known=routed.selected.cost_known,
        cost_micro_usd=routed.selected.cost_micro_usd,
    )
    if response.status != "ok" or response.output is None:
        gaps.append(_gap("model_unavailable", None, f"model status {response.status}"))
        return [], ref
    try:
        parsed = ModelFindings.model_validate_json(json.dumps(response.output))
    except (ValidationError, ValueError):
        gaps.append(_gap("model_output_invalid", None, "output failed validation"))
        return [], ref
    allowed = set(sent)
    accepted = [f for f in parsed.findings if set(f.evidence_ids) <= allowed]
    dropped = len(parsed.findings) - len(accepted)
    if dropped:
        gaps.append(_gap("uncited_finding_dropped", None, f"{dropped} dropped"))
    return accepted, ref


def make_saved_evidence_handler(
    deps: SpecialistDeps,
    org_id: str,
    incident_id: str,
    evidence_ids: tuple[str, ...],
) -> JobHandler:
    """Analyze an administrator-selected snapshot without recollecting telemetry.

    Model admission still checks every canonical evidence reference, its tenant,
    incident, immutable hash, classification, role policy and budget.
    """
    if not evidence_ids or len(evidence_ids) > MAX_MODEL_EVIDENCE:
        raise ValueError("Select between one and sixteen evidence records")

    async def handler(ctx: JobContext) -> JsonValue:
        if (
            ctx.task.org_id != org_id
            or ctx.lease.incident_id != incident_id
            or ctx.task.role != "triage"
        ):
            raise ValueError("Saved-evidence analysis scope mismatch")
        gaps = [
            _gap(
                "coverage_partial",
                None,
                "Saved historical evidence; sensor completeness remains unverified",
            )
        ]
        findings, model = await _model_step(ctx, deps, list(evidence_ids), gaps)
        result = _finalize("triage", [], list(evidence_ids), findings, gaps, model)
        return cast("JsonValue", result.model_dump(mode="json"))

    return handler


def make_specialist_handler(  # noqa: C901, PLR0915
    spec: RoleSpec, deps: SpecialistDeps
) -> JobHandler:
    """Build the scheduler handler; the returned value is plain JSON."""

    async def handler(  # noqa: C901, PLR0912, PLR0915 - ordered guarded execution
        ctx: JobContext,
    ) -> JsonValue:
        calls: list[ToolCallRecord] = []
        evidence: list[str] = []
        gaps: list[SpecialistGap] = []
        if ctx.task.role != spec.role:
            result = _finalize(
                spec.role,
                calls,
                evidence,
                [],
                [_gap("role_mismatch", None, "task role differs from handler role")],
                None,
                error=True,
            )
            return cast("JsonValue", result.model_dump(mode="json"))
        await ctx.checkpoint()
        org_id = ctx.task.org_id  # only trusted source of tenancy
        service = deps.read_service_for(org_id)
        if deps.help_context_for is not None:
            try:
                help_context = deps.help_context_for(org_id, ctx.task.task_id)
            except Exception:
                _LOGGER.warning("specialist help context lookup failed", exc_info=True)
                gaps.append(
                    _gap("help_context_unavailable", None, "help context denied")
                )
                help_context = None
            if help_context is not None:
                evidence.extend(help_context.shared_evidence_ids)
        plan = spec.plan
        if len(plan) > MAX_TOOL_CALLS:
            plan = plan[:MAX_TOOL_CALLS]
            gaps.append(_gap("coverage_partial", None, "plan capped at 20 calls"))
        if service is None or service.org_id != org_id:
            gaps.append(_gap("service_not_configured", None, "no read service"))
            service, plan = None, ()
        for step in plan:
            if service is None:
                break
            await ctx.checkpoint()  # refreshes ctx.lease; never reuse contexts
            qctx = QueryContext(
                _incident_time(deps, org_id, ctx.lease.incident_id),
                authentication_incident=(
                    deps.authentication_incident_for(org_id, ctx.lease.incident_id)
                    if deps.authentication_incident_for
                    else False
                ),
            )
            try:
                query = step.build_query(ctx.task, qctx)
            except (ValueError, TypeError, LookupError):
                gaps.append(_gap("query_unavailable", step.tool_id, "query not built"))
                continue
            cited = tuple(dict.fromkeys(evidence))[:MAX_CITATIONS]
            if step.cite_run_evidence and not cited:
                gaps.append(
                    _gap("coverage_partial", step.tool_id, "no run evidence to cite")
                )
                continue
            try:
                context = service.contexts.build(ctx.lease, deps.actor_user_id)
            except (ReadContextDeniedError, LookupError):
                # A cancelled/lost lease surfaces as an exception, not a gap.
                await ctx.checkpoint()
                gaps.append(_gap("context_denied", step.tool_id, "context denied"))
                break
            try:
                if step.cite_run_evidence:
                    with cited_evidence_ids(cited):
                        tool_result = await service.gateway.execute(
                            step.tool_id, query, context=context
                        )
                else:
                    tool_result = await service.gateway.execute(
                        step.tool_id, query, context=context
                    )
            except JobLeaseLostError:
                raise
            except Exception:
                _LOGGER.warning("specialist read failed", exc_info=True)
                gaps.append(_gap("tool_unavailable", step.tool_id, "read failed"))
                continue
            ids = [e.evidence_id for e in tool_result.evidence]
            calls.append(
                ToolCallRecord(
                    tool_id=step.tool_id[:200],
                    status=tool_result.status,
                    error_code=tool_result.error_code,
                    evidence_count=min(len(ids), 1000),
                )
            )
            evidence.extend(ids)
            gaps.extend(_classify(tool_result))
        evidence = list(dict.fromkeys(evidence))
        findings, model = await _model_step(ctx, deps, evidence, gaps)
        final = _finalize(spec.role, calls, evidence, findings, gaps, model)
        return cast("JsonValue", final.model_dump(mode="json"))

    return handler
