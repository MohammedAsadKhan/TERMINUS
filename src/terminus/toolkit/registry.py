"""Immutable operator-installed executables, separate from roadmap metadata.

Construct this registry in trusted application composition code. Neither a model
tool name nor a catalog availability label installs a handler or a connector.
Connector readiness is a deployment snapshot; tenant permissions remain the
gateway's responsibility on every invocation.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from terminus.toolkit.catalog import CORE_ROLES, ToolkitCatalog, load_catalog
from terminus.toolkit.models import (
    ReadQuery,
    ToolDescriptor,
    ToolExecutionContext,
    ToolResult,
)

ToolHandler = Callable[[ToolExecutionContext, ReadQuery], Awaitable[ToolResult]]


class ToolRegistryError(ValueError):
    """An executable cannot be resolved, with a safe model-facing error code."""

    error_code: str
    status: Literal["unsupported", "denied", "unavailable"]

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        status: Literal["unsupported", "denied", "unavailable"],
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status = status


@dataclass(frozen=True, slots=True)
class InstalledTool:
    """Explicit trusted async handler and its exact catalog contract."""

    descriptor: ToolDescriptor
    handler: ToolHandler


@dataclass(frozen=True, slots=True, init=False)
class ExecutableToolRegistry:
    """A fixed, validated set of read-only v1 executables and role grants."""

    _descriptors: Mapping[str, ToolDescriptor]
    _handlers: Mapping[str, ToolHandler]
    _grants: Mapping[str, frozenset[str]]
    _configured_connector_ids: frozenset[str]

    def __init__(
        self,
        catalog: ToolkitCatalog | None = None,
        *,
        installed: Iterable[InstalledTool] = (),
        configured_connector_ids: Iterable[str] = (),
    ) -> None:
        source = load_catalog() if catalog is None else catalog
        # Revalidate to reject model_copy/model_construct bypasses and detach
        # the registry's immutable descriptors from caller-owned metadata.
        source = ToolkitCatalog.model_validate(source.model_dump())
        descriptors = {item.tool_id: item for item in source.tools}
        configured = frozenset(configured_connector_ids)
        if not configured <= {item.connector_id for item in source.connectors}:
            raise ValueError("Configured connector is absent from the catalog")
        handlers: dict[str, ToolHandler] = {}
        for entry in installed:
            self._validate_installation(entry, descriptors, handlers)
            handlers[entry.descriptor.tool_id] = entry.handler
        grants = {
            bundle.role: frozenset(
                tool_id
                for tool_id in bundle.tool_ids
                if bundle.role in descriptors[tool_id].permitted_roles
                and descriptors[tool_id].release == "1.0"
            )
            for bundle in source.core_bundles
        }
        object.__setattr__(self, "_descriptors", MappingProxyType(descriptors))
        object.__setattr__(self, "_handlers", MappingProxyType(handlers))
        object.__setattr__(self, "_grants", MappingProxyType(grants))
        object.__setattr__(self, "_configured_connector_ids", configured)

    @staticmethod
    def _validate_installation(
        entry: InstalledTool,
        descriptors: Mapping[str, ToolDescriptor],
        handlers: Mapping[str, ToolHandler],
    ) -> None:
        descriptor = ToolDescriptor.model_validate(entry.descriptor.model_dump())
        if descriptor.tool_id in handlers:
            raise ValueError("Duplicate executable registration")
        if descriptor != descriptors.get(descriptor.tool_id):
            raise ValueError("Installed descriptor must exactly match the catalog")
        if (
            descriptor.release != "1.0"
            or descriptor.effect not in {"read", "local_analysis"}
            or descriptor.input_contract != "read_query"
            or descriptor.egress != "none"
            or descriptor.requires_approval
        ):
            raise ValueError("Only v1 read/local analysis without egress may execute")
        if not (
            inspect.iscoroutinefunction(entry.handler)
            or inspect.iscoroutinefunction(
                getattr(entry.handler, "__call__", None)  # noqa: B004 - async callable
            )
        ):
            raise ValueError("Executable handler must be asynchronous")

    def grants_for(self, role: str) -> frozenset[str]:
        """Return catalog bundle grants; these alone never enable execution."""
        if role not in CORE_ROLES:
            raise ToolRegistryError(
                "Only the eight core roles may execute tools",
                error_code="role_not_supported",
                status="denied",
            )
        return self._grants[role]

    def descriptor(self, tool_id: str) -> ToolDescriptor:
        """Return operational availability without changing the catalog."""
        descriptor = self._descriptors.get(tool_id)
        if descriptor is None:
            raise ToolRegistryError(
                "Unknown tool",
                error_code="tool_not_supported",
                status="unsupported",
            )
        availability = descriptor.availability
        if tool_id in self._handlers:
            availability = (
                "available"
                if set(descriptor.connector_ids) <= self._configured_connector_ids
                else "not_configured"
            )
        return ToolDescriptor.model_validate(
            descriptor.model_dump() | {"availability": availability}
        )

    def resolve(self, tool_id: str, role: str) -> InstalledTool:
        """Resolve a role-granted executable; context admission follows later."""
        grants = self.grants_for(role)
        descriptor = self.descriptor(tool_id)
        if descriptor.release != "1.0" or tool_id not in grants:
            raise ToolRegistryError(
                "Tool is outside the core role's v1 bundle",
                error_code="tool_not_granted",
                status="denied",
            )
        handler = self._handlers.get(tool_id)
        if handler is None:
            raise ToolRegistryError(
                "Tool implementation is not installed",
                error_code="tool_not_installed",
                status="unavailable",
            )
        if descriptor.availability != "available":
            raise ToolRegistryError(
                "Tool connector is not configured",
                error_code="connector_not_configured",
                status="unavailable",
            )
        return InstalledTool(descriptor, handler)
