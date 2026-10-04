"""Execution requires an explicit async install, readiness and a core grant."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import cast

import pytest
from pydantic import ValidationError

from terminus.toolkit.catalog import CORE_ROLES, load_catalog
from terminus.toolkit.models import (
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
    ToolResult,
)
from terminus.toolkit.registry import (
    ExecutableToolRegistry,
    InstalledTool,
    ToolHandler,
    ToolRegistryError,
)


async def handler(_context: ToolExecutionContext, _query: ReadQuery) -> ToolResult:
    """This test handler is resolved, never invoked without gateway admission."""
    return ToolResult(tool_id="incident.get", version="1.0", status="unavailable")


def sync_handler(_context: ToolExecutionContext, _query: ReadQuery) -> ToolResult:
    return ToolResult(tool_id="incident.get", version="1.0", status="unavailable")


def tool(tool_id: str = "incident.get") -> ToolDescriptor:
    return next(item for item in load_catalog().tools if item.tool_id == tool_id)


def test_catalog_names_and_connector_readiness_never_install_handlers():
    catalog = load_catalog()
    registry = ExecutableToolRegistry(
        catalog, configured_connector_ids=("terminus_store",)
    )
    assert registry.descriptor("incident.get").availability != "available"
    with pytest.raises(ToolRegistryError) as failure:
        _ = registry.resolve("incident.get", "triage")
    assert failure.value.status == "unavailable"
    assert failure.value.error_code == "tool_not_installed"
    assert all(item.availability != "available" for item in catalog.tools)


def test_explicit_installation_requires_all_connectors_and_preserves_catalog():
    catalog = load_catalog()
    installed = InstalledTool(tool("collection.coverage"), handler)
    incomplete = ExecutableToolRegistry(
        catalog,
        installed=(installed,),
        configured_connector_ids=("wazuh_manager",),
    )
    assert incomplete.descriptor("collection.coverage").availability == "not_configured"
    with pytest.raises(ToolRegistryError) as failure:
        _ = incomplete.resolve("collection.coverage", "triage")
    assert failure.value.error_code == "connector_not_configured"
    ready = ExecutableToolRegistry(
        catalog,
        installed=(installed,),
        configured_connector_ids=("wazuh_manager", "wazuh_indexer"),
    )
    resolved = ready.resolve("collection.coverage", "triage")
    assert resolved.handler is handler
    assert resolved.descriptor.availability == "available"
    assert installed.descriptor.availability != "available"
    assert all(item.availability != "available" for item in catalog.tools)


def test_connector_free_local_analysis_requires_explicit_installation():
    registry = ExecutableToolRegistry(
        installed=(InstalledTool(tool("payload.decode"), handler),)
    )
    assert (
        registry.resolve("payload.decode", "endpoint").descriptor.effect
        == "local_analysis"
    )
    with pytest.raises(ToolRegistryError) as failure:
        _ = ExecutableToolRegistry().resolve("payload.decode", "endpoint")
    assert failure.value.status == "unavailable"


def test_exact_eight_core_grants_intersect_bundle_and_descriptor_permissions():
    catalog = load_catalog()
    registry = ExecutableToolRegistry(
        catalog, installed=(InstalledTool(tool("evidence.get"), handler),)
    )
    for bundle in catalog.core_bundles:
        assert registry.grants_for(bundle.role) == frozenset(bundle.tool_ids)
    assert {bundle.role for bundle in catalog.core_bundles} == CORE_ROLES
    # The descriptor grants triage, but the triage bundle deliberately does not.
    assert "triage" in tool("evidence.get").permitted_roles
    with pytest.raises(ToolRegistryError) as failure:
        _ = registry.resolve("evidence.get", "triage")
    assert failure.value.status == "denied"
    assert registry.resolve("evidence.get", "response_planner").handler is handler


@pytest.mark.parametrize("role", ["admin", "cloud_security_analyst", "", "Triage"])
def test_future_and_unknown_roles_cannot_resolve_tools(role: str):
    registry = ExecutableToolRegistry(
        installed=(InstalledTool(tool(), handler),),
        configured_connector_ids=("terminus_store",),
    )
    with pytest.raises(ToolRegistryError) as failure:
        _ = registry.resolve("incident.get", role)
    assert failure.value.error_code == "role_not_supported"


def test_unknown_and_future_tools_are_unexecutable():
    registry = ExecutableToolRegistry()
    with pytest.raises(ToolRegistryError) as failure:
        _ = registry.resolve("made.up", "triage")
    assert failure.value.status == "unsupported"
    future = next(item for item in load_catalog().tools if item.release == "future")
    with pytest.raises(ToolRegistryError) as failure:
        _ = registry.resolve(future.tool_id, "triage")
    assert failure.value.status == "denied"
    with pytest.raises(ValueError, match="Only v1"):
        _ = ExecutableToolRegistry(installed=(InstalledTool(future, handler),))


@pytest.mark.parametrize(
    "tool_id",
    [
        "indicators.reputation",
        "response.propose",
        "response.wazuh_ip_block",
        "recovery.wazuh_ip_unblock",
    ],
)
def test_egress_proposal_and_dispatch_handlers_cannot_be_installed(tool_id: str):
    with pytest.raises(ValueError, match="Only v1"):
        _ = ExecutableToolRegistry(installed=(InstalledTool(tool(tool_id), handler),))


def test_duplicate_mismatching_sync_and_unknown_registrations_are_rejected():
    entry = InstalledTool(tool(), handler)
    with pytest.raises(ValueError, match="Duplicate"):
        _ = ExecutableToolRegistry(installed=(entry, entry))
    for descriptor in (
        entry.descriptor.model_copy(update={"availability": "available"}),
        entry.descriptor.model_copy(update={"permitted_roles": ("verification",)}),
        entry.descriptor.model_copy(update={"tool_id": "fake.tool"}),
    ):
        with pytest.raises(ValueError, match="exactly match"):
            _ = ExecutableToolRegistry(installed=(InstalledTool(descriptor, handler),))
    with pytest.raises(ValueError, match="asynchronous"):
        _ = ExecutableToolRegistry(
            installed=(InstalledTool(tool(), cast(ToolHandler, sync_handler)),)
        )
    with pytest.raises(ValueError, match="absent"):
        _ = ExecutableToolRegistry(configured_connector_ids=("made.up",))
    with pytest.raises(ValidationError):
        _ = ExecutableToolRegistry(
            installed=(
                InstalledTool(tool().model_copy(update={"version": "9"}), handler),
            )
        )


def test_registry_snapshots_and_descriptors_are_immutable():
    entries = [InstalledTool(tool(), handler)]
    connectors = ["terminus_store"]
    registry = ExecutableToolRegistry(
        installed=entries, configured_connector_ids=connectors
    )
    entries.clear()
    connectors.clear()
    resolved = registry.resolve("incident.get", "triage")
    assert resolved.handler is handler
    with pytest.raises(FrozenInstanceError):
        setattr(registry, "_configured_connector_ids", frozenset())  # noqa: B010
    with pytest.raises(TypeError):
        cast(dict[str, ToolHandler], getattr(registry, "_handlers"))["incident.get"] = (  # noqa: B009
            handler
        )
    with pytest.raises(ValidationError):
        resolved.descriptor.availability = "planned"
