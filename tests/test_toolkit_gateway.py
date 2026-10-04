"""Explicit recorded callbacks exercise admission, durability and stale fencing."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database
from terminus.toolkit.audit import ToolInvocationStore, canonical_query_digest
from terminus.toolkit.catalog import ToolkitCatalog, load_catalog
from terminus.toolkit.evidence import ToolEvidenceWriter
from terminus.toolkit.gateway import ToolGateway
from terminus.toolkit.models import (
    EvidenceReference,
    Provenance,
    ReadQuery,
    ToolExecutionContext,
    ToolResult,
)
from terminus.toolkit.registry import ExecutableToolRegistry, InstalledTool
from terminus.toolkit.validation import ToolContractValidator

NOW = datetime(2026, 10, 4, 6, 0, tzinfo=UTC)
TOOL = "incident.get"


@pytest.fixture
def runtime(tmp_path):
    db = Database(str(tmp_path / "gateway.db"))
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("a", "Fixture organization", NOW.isoformat()),
    )
    for incident in ("incident-1", "incident-2"):
        db.execute(
            "INSERT INTO incidents(ticket_id,org_id,alert_id,severity,confidence,summary,recommended_actions,policy_tier,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                incident,
                "a",
                incident,
                "high",
                "high",
                "Fixture",
                "[]",
                "standard",
                NOW.isoformat(),
            ),
        )
    scheduler = SchedulerStore(db, clock=lambda: NOW)
    task = scheduler.records.create_incident_task(
        "a",
        "incident-1",
        "alert_handling",
        "triage",
        "Inspect recorded fixture",
    )
    scheduler.enqueue_task("a", task.task_id)
    scheduler.acquire_coordinator("owner")
    lease = scheduler.claim_next("owner", "worker", ["triage"])
    assert lease is not None
    context = ToolExecutionContext(
        org_id="a",
        incident_id=task.incident_id,
        task_id=task.task_id,
        run_id=lease.run_id,
        role="triage",
        granted_tool_ids=(TOOL,),
        permitted_resource_ids=("host-1",),
        permitted_connector_ids=("terminus_store",),
        policy_version="policy-v1",
        budget_reservation_id="fixture-budget",
        invocation_count=0,
        lease=lease,
    )
    validator = ToolContractValidator(scheduler)
    audit = ToolInvocationStore(db, clock=scheduler._now)
    catalog = load_catalog()
    source = next(item for item in catalog.tools if item.tool_id == TOOL)
    writer = ToolEvidenceWriter(validator, audit)
    query = ReadQuery(resource_id="host-1", start=NOW - timedelta(minutes=30), end=NOW)

    def gateway(handler, *, installed=True, configured=True, limits=None):
        local_catalog = catalog
        local_descriptor = source
        if limits:
            local_descriptor = source.model_copy(
                update={"limits": source.limits.model_copy(update=limits)}
            )
            local_catalog = ToolkitCatalog.model_validate(
                catalog.model_dump()
                | {
                    "tools": tuple(
                        local_descriptor if item.tool_id == TOOL else item
                        for item in catalog.tools
                    ),
                },
            )
        registry = ExecutableToolRegistry(
            local_catalog,
            installed=(InstalledTool(local_descriptor, handler),) if installed else (),
            configured_connector_ids=("terminus_store",) if configured else (),
        )
        return ToolGateway(registry, validator, audit)

    def observed_result(context, query):
        evidence, provenance = writer.record(
            source.model_copy(update={"availability": "available"}),
            context,
            query,
            connector_id="terminus_store",
            connector_version="1.0",
            source_id="recorded-fixture",
            source_timestamp=NOW,
            content={"event": "authentication_failure"},
            source_event_ids=("event-1",),
        )
        return ToolResult(
            tool_id=TOOL,
            version="1.0",
            status="ok",
            data={"event": "authentication_failure"},
            evidence=(evidence,),
            provenance=(provenance,),
            coverage="complete",
        )

    def empty_result(query):
        return ToolResult(
            tool_id=TOOL,
            version="1.0",
            status="empty",
            coverage="complete",
            provenance=(
                Provenance(
                    source_id="recorded-fixture",
                    connector_id="terminus_store",
                    connector_version="1.0",
                    source_event_ids=(),
                    source_timestamp=NOW,
                    collected_at=NOW,
                    query_digest=canonical_query_digest(query),
                ),
            ),
        )

    yield scheduler, context, audit, query, gateway, observed_result, empty_result
    db.close()


@pytest.mark.asyncio
async def test_handler_has_durable_reservation_before_io_and_result_survives_restart(
    runtime,
):
    scheduler, context, audit, query, gateway, observed, _ = runtime

    async def handler(ctx, args):
        assert audit.count(ctx.org_id, ctx.task_id) == 1
        assert len(audit.list_pending(ctx.org_id, ctx.task_id)) == 1
        return observed(ctx, args)

    result = await gateway(handler).execute(
        TOOL, query.model_dump(mode="json"), context=context
    )
    assert result.status == "ok"
    assert result.evidence
    invocation = audit.list_invocations("a", context.task_id)[0]
    assert invocation.outcome == "ok"
    assert invocation.connector_id == "terminus_store"
    assert invocation.connector_version == "1.0"
    assert invocation.connector_versions == (("terminus_store", "1.0"),)
    assert invocation.arguments_digest == canonical_query_digest(query)
    assert invocation.evidence_ids == (result.evidence[0].evidence_id,)
    reopened_db = Database(scheduler.db.db_path)
    reopened = ToolInvocationStore(reopened_db, clock=lambda: NOW)
    assert reopened.count("a", context.task_id) == 1
    assert reopened.list_invocations("a", context.task_id) == [invocation]
    assert reopened.list_invocations("foreign-org", context.task_id) == []
    assert "authentication_failure" not in invocation.model_dump_json()
    reopened_db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra",
    [
        {"org_id": "b"},
        {"command": "whoami"},
        {"url": "https://example.test"},
        {"credentials": "secret"},
        {"policy_version": "other"},
        {"page_size": "200"},
    ],
)
async def test_model_scope_credentials_and_coercion_never_reach_handler(runtime, extra):
    _, context, audit, query, gateway, _, empty = runtime
    calls = []

    async def handler(ctx, args):
        calls.append(True)
        return empty(args)

    result = await gateway(handler).execute(
        TOOL,
        query.model_dump(mode="json") | extra,
        context=context,
    )
    assert result.status == "denied"
    assert result.error_code == "invalid_arguments"
    assert calls == []
    assert audit.count("a", context.task_id) == 0
    assert audit.list_invocations("a", context.task_id)[0].policy_decision == "denied"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("absent", "unavailable"),
        ("unconfigured", "unavailable"),
        ("unknown", "unsupported"),
        ("wrong-role", "denied"),
        ("invalid-name", "unsupported"),
    ],
)
async def test_uninstalled_unconfigured_unknown_and_ungranted_tools_are_honest(
    runtime, mode, status
):
    _, context, audit, query, gateway, _, _ = runtime

    async def handler(ctx, args):
        pytest.fail("Denied handler ran")

    gate = gateway(
        handler, installed=mode != "absent", configured=mode != "unconfigured"
    )
    tool_id = {
        "unknown": "unknown.tool",
        "wrong-role": "identity.auth_events",
        "invalid-name": "../../import",
    }.get(mode, TOOL)
    result = await gate.execute(tool_id, query, context=context)
    assert result.status == status
    assert result.data is None
    assert result.evidence == ()
    assert audit.count("a", context.task_id) == 0
    assert len(audit.list_invocations("a", context.task_id)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        {"granted_tool_ids": ()},
        {"permitted_resource_ids": ()},
        {"permitted_connector_ids": ()},
        {"cancelled": True},
        {"invocation_count": 20},
    ],
)
async def test_trusted_context_permissions_are_checked_before_io(runtime, change):
    _, context, audit, query, gateway, _, _ = runtime

    async def handler(ctx, args):
        pytest.fail("Denied handler ran")

    result = await gateway(handler).execute(
        TOOL, query, context=context.model_copy(update=change)
    )
    assert result.status == "denied"
    assert audit.count("a", context.task_id) == 0


@pytest.mark.asyncio
async def test_twenty_attempts_are_durable_across_gateway_restart_and_concurrent_calls(
    runtime,
):
    scheduler, context, audit, query, gateway, _, empty = runtime
    calls = []

    async def handler(ctx, args):
        calls.append(True)
        await asyncio.sleep(0)
        return empty(args)

    gate = gateway(handler)
    results = await asyncio.gather(
        *(gate.execute(TOOL, query, context=context) for _ in range(21))
    )
    assert len(calls) == 20
    assert sum(item.status == "empty" for item in results) == 20
    assert results[-1].error_code == "quota_exhausted"
    reopened = ToolInvocationStore(scheduler.db, clock=lambda: NOW)
    gate = ToolGateway(gate.registry, gate.validator, reopened)
    assert (
        await gate.execute(TOOL, query, context=context)
    ).error_code == "quota_exhausted"
    assert audit.count("a", context.task_id) == 20


@pytest.mark.asyncio
@pytest.mark.parametrize("loss", ["cancel", "expired"])
async def test_ownership_loss_after_collection_suppresses_result_and_audits_unknown(
    runtime, loss
):
    scheduler, context, audit, query, gateway, observed, _ = runtime

    async def handler(ctx, args):
        result = observed(ctx, args)
        if loss == "cancel":
            scheduler.request_cancel("a", ctx.task_id)
        else:
            scheduler.clock = lambda: NOW + timedelta(seconds=60)
        return result

    result = await gateway(handler).execute(TOOL, query, context=context)
    assert result.status == "error"
    assert result.error_code == "execution_unknown"
    assert result.data is None
    assert result.evidence == ()
    invocation = audit.list_invocations("a", context.task_id)[0]
    assert invocation.outcome == "unknown"
    assert invocation.evidence_ids == ()


@pytest.mark.asyncio
async def test_timeout_is_bounded_even_when_handler_suppresses_cancellation(runtime):
    _, context, audit, query, gateway, _, empty = runtime
    released = asyncio.Event()
    settled = asyncio.Event()

    async def handler(ctx, args):
        try:
            await released.wait()
        except asyncio.CancelledError:
            await released.wait()
        finally:
            settled.set()
        return empty(args)

    gate = gateway(handler, limits={"timeout_seconds": 1})
    result = await asyncio.wait_for(
        gate.execute(TOOL, query, context=context), timeout=2
    )
    assert result.error_code == "execution_unknown"
    assert audit.list_invocations("a", context.task_id)[0].outcome == "unknown"
    released.set()
    await settled.wait()
    await asyncio.sleep(0)
    assert audit.list_invocations("a", context.task_id)[0].outcome == "unknown"


@pytest.mark.asyncio
async def test_caller_cancellation_is_audited_before_propagating(runtime):
    _, context, audit, query, gateway, _, _ = runtime
    started = asyncio.Event()

    async def handler(ctx, args):
        started.set()
        await asyncio.Event().wait()

    invocation = asyncio.create_task(
        gateway(handler).execute(TOOL, query, context=context)
    )
    await started.wait()
    invocation.cancel()
    with pytest.raises(asyncio.CancelledError):
        await invocation
    assert audit.list_invocations("a", context.task_id)[0].outcome == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "hash",
        "missing",
        "foreign",
        "query",
        "connector",
        "time",
        "unpersisted",
        "identity",
        "bounds",
        "invented-findings",
        "empty-no-provenance",
    ],
)
async def test_result_forgery_bounds_and_missing_provenance_are_rejected(runtime, bad):
    scheduler, context, audit, query, gateway, observed, _ = runtime

    async def handler(ctx, args):  # noqa: PLR0911 - independently forged boundaries
        result = observed(ctx, args)
        reference = result.evidence[0]
        if bad == "hash":
            return result.model_copy(
                update={
                    "evidence": (
                        reference.model_copy(update={"content_hash": "0" * 64}),
                    )
                }
            )
        if bad == "missing":
            return result.model_copy(
                update={
                    "evidence": (
                        reference.model_copy(update={"evidence_id": "missing"}),
                    )
                }
            )
        if bad == "foreign":
            task = scheduler.records.create_incident_task(
                "a", "incident-2", "investigation", "identity", "Other incident"
            )
            record = scheduler.records.create_evidence(
                "a", task.task_id, "fixture", NOW, content={"event": "other"}
            )
            return result.model_copy(
                update={
                    "evidence": (
                        EvidenceReference(
                            evidence_id=record.evidence_id,
                            org_id="a",
                            incident_id=ctx.incident_id,
                            content_hash=record.content_hash,
                        ),
                    )
                }
            )
        if bad in {"query", "connector", "time"}:
            updates = {
                "query": {"query_digest": "0" * 64},
                "connector": {"connector_id": "foreign-source"},
                "time": {"source_timestamp": NOW + timedelta(seconds=1)},
            }[bad]
            return result.model_copy(
                update={
                    "provenance": (result.provenance[0].model_copy(update=updates),)
                }
            )
        if bad == "unpersisted":
            return result.model_copy(update={"evidence": ()})
        if bad == "identity":
            return result.model_copy(update={"tool_id": "other.tool"})
        if bad == "bounds":
            return result.model_copy(update={"data": "x" * 65536})
        if bad == "invented-findings":
            return result.model_copy(update={"data": {"event": "invented_compromise"}})
        return ToolResult(
            tool_id=TOOL, version="1.0", status="empty", coverage="complete"
        )

    result = await gateway(handler).execute(TOOL, query, context=context)
    assert result.status == "error"
    assert result.error_code == "invalid_result"
    assert result.data is None
    assert result.evidence == ()
    assert audit.list_invocations("a", context.task_id)[0].outcome == "error"


@pytest.mark.asyncio
async def test_handler_exception_never_exposes_secrets_and_remains_audited(runtime):
    _, context, audit, query, gateway, _, _ = runtime

    async def handler(ctx, args):
        raise RuntimeError("secret credential in provider exception")

    result = await gateway(handler).execute(TOOL, query, context=context)
    assert result.error_code == "handler_failed"
    assert "secret" not in result.model_dump_json()
    assert audit.list_invocations("a", context.task_id)[0].outcome == "error"


@pytest.mark.asyncio
async def test_failed_audit_prevents_handler_io(runtime, monkeypatch):
    _, context, audit, query, gateway, _, _ = runtime

    async def handler(ctx, args):
        pytest.fail("Unaudited handler ran")

    def broken(*args):
        raise RuntimeError("Database unavailable")

    monkeypatch.setattr(audit, "reserve", broken)
    result = await gateway(handler).execute(TOOL, query, context=context)
    assert result.status == "unavailable"
    assert result.error_code == "audit_unavailable"
    assert audit.count("a", context.task_id) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "arguments",
    ["x" * 65537, {"resource_id": "x" * 65537}, "é" * 33000],
    ids=["oversized-string", "oversized-object", "oversized-utf8"],
)
async def test_arguments_are_bounded_before_parsing_or_handler_execution(
    runtime, arguments
):
    _, context, audit, _, gateway, _, _ = runtime

    async def handler(ctx, args):
        pytest.fail("Oversized arguments reached handler")

    result = await gateway(handler).execute(TOOL, arguments, context=context)
    assert result.error_code == "arguments_too_large"
    assert result.status == "denied"
    assert audit.count("a", context.task_id) == 0
    assert len(audit.list_invocations("a", context.task_id)) == 1


@pytest.mark.asyncio
async def test_excess_denials_are_bounded_and_do_not_enter_handler(runtime):
    _, context, audit, query, gateway, _, _ = runtime

    async def handler(ctx, args):
        pytest.fail("Invalid arguments reached handler")

    gate = gateway(handler)
    arguments = query.model_dump(mode="json") | {"command": "whoami"}
    results = [await gate.execute(TOOL, arguments, context=context) for _ in range(21)]
    assert results[-1].status == "denied"
    assert results[-1].error_code == "denial_quota_exhausted"
    assert len(audit.list_invocations("a", context.task_id)) == 20
    assert audit.count("a", context.task_id) == 0


@pytest.mark.asyncio
async def test_cancellation_is_polled_while_handler_is_waiting(runtime):
    scheduler, context, audit, query, gateway, _, _ = runtime
    started = asyncio.Event()

    async def handler(ctx, args):
        started.set()
        await asyncio.Event().wait()

    invocation = asyncio.create_task(
        gateway(handler).execute(TOOL, query, context=context)
    )
    await started.wait()
    scheduler.request_cancel("a", context.task_id)
    result = await asyncio.wait_for(invocation, timeout=0.5)
    assert result.error_code == "execution_unknown"
    assert audit.list_invocations("a", context.task_id)[0].outcome == "unknown"


@pytest.mark.asyncio
async def test_late_evidence_cannot_be_written_after_deadline(runtime):
    scheduler, context, audit, query, gateway, observed, _ = runtime
    released = asyncio.Event()
    settled = asyncio.Event()
    late_errors = []

    async def handler(ctx, args):
        try:
            await released.wait()
        except asyncio.CancelledError:
            await released.wait()
        try:
            return observed(ctx, args)
        except ValueError as exc:
            late_errors.append(exc)
            return ToolResult(tool_id=TOOL, version="1.0", status="error")
        finally:
            settled.set()

    gate = gateway(handler, limits={"timeout_seconds": 1})
    result = await asyncio.wait_for(
        gate.execute(TOOL, query, context=context), timeout=2
    )
    assert result.error_code == "execution_unknown"
    released.set()
    await settled.wait()
    await asyncio.sleep(0)
    assert len(late_errors) == 1
    assert scheduler.records.list_evidence("a", incident_id=context.incident_id) == []
    assert audit.list_invocations("a", context.task_id)[0].outcome == "unknown"


@pytest.mark.asyncio
async def test_prior_incident_evidence_cannot_be_relabeled_as_a_fresh_read(runtime):
    _, context, audit, query, gateway, observed, _ = runtime
    prior = []

    async def handler(ctx, args):
        if not prior:
            result = observed(ctx, args)
            prior.append(result)
            return result
        result = prior[0]
        provenance = result.provenance[0].model_copy(
            update={"query_digest": canonical_query_digest(args)}
        )
        return result.model_copy(update={"provenance": (provenance,)})

    gate = gateway(handler)
    first = await gate.execute(TOOL, query, context=context)
    assert first.status == "ok"
    fresh = query.model_copy(update={"start": NOW - timedelta(minutes=10)})
    second = await gate.execute(TOOL, fresh, context=context)
    assert second.error_code == "invalid_result"
    assert second.evidence == ()
    assert sorted(
        item.outcome for item in audit.list_invocations("a", context.task_id)
    ) == ["error", "ok"]


@pytest.mark.asyncio
async def test_multiple_read_records_return_their_observations_in_reference_order(
    runtime,
):
    _, context, _, query, gateway, observed, _ = runtime

    async def handler(ctx, args):
        first = observed(ctx, args)
        second = observed(ctx, args)
        return ToolResult(
            tool_id=TOOL,
            version="1.0",
            status="ok",
            coverage="complete",
            data=[first.data, second.data],
            evidence=first.evidence + second.evidence,
            provenance=first.provenance + second.provenance,
        )

    result = await gateway(handler).execute(TOOL, query, context=context)
    assert result.status == "ok"
    assert len(result.evidence) == 2
    assert result.data == [
        {"event": "authentication_failure"},
        {"event": "authentication_failure"},
    ]
