"""Assemble and validate roadmap metadata, never an executable registry."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Annotated, Literal

from pydantic import Field, model_validator

from terminus.toolkit.models import (
    Availability,
    Contract,
    CoreRole,
    Id,
    Text,
    ToolDescriptor,
)

CORE_ROLES = frozenset(
    {
        "triage",
        "identity",
        "endpoint",
        "network",
        "response_planner",
        "verification",
        "evidence_reporting",
        "application_api",
    }
)


class ConnectorDescriptor(Contract):
    connector_id: Id
    name: Text
    availability: Availability
    capabilities: tuple[Id, ...]
    credential_scope: Literal["organization"]
    egress: Literal["none", "policy_required"]
    acceptance_checks: Annotated[tuple[Text, ...], Field(min_length=1)]


class SpecialtyDescriptor(Contract):
    specialty_id: Id
    name: Text
    area: Literal[
        "alert_handling",
        "investigation",
        "infrastructure",
        "applications_data",
        "response_improvement",
    ]
    availability: Literal["planned", "implementation_pending"]
    core_role: CoreRole | None
    tool_ids: Annotated[tuple[Id, ...], Field(min_length=1)]
    telemetry: Annotated[tuple[Text, ...], Field(min_length=1)]
    permissions: Annotated[tuple[Text, ...], Field(min_length=1)]
    expected_evidence: Annotated[tuple[Text, ...], Field(min_length=1)]
    acceptance_checks: Annotated[tuple[Text, ...], Field(min_length=1)]


class CoreBundle(Contract):
    role: CoreRole
    tool_ids: Annotated[tuple[Id, ...], Field(min_length=1)]
    max_invocations: Literal[20]
    availability: Literal["implementation_pending"]


class ToolkitCatalog(Contract):
    connectors: tuple[ConnectorDescriptor, ...]
    tools: tuple[ToolDescriptor, ...]
    specialties: Annotated[
        tuple[SpecialtyDescriptor, ...], Field(min_length=60, max_length=60)
    ]
    core_bundles: Annotated[tuple[CoreBundle, ...], Field(min_length=8, max_length=8)]

    @model_validator(mode="after")
    def coherent_non_executable_catalog(self) -> ToolkitCatalog:  # noqa: C901, PLR0912
        tools = {item.tool_id: item for item in self.tools}
        connectors = {item.connector_id: item for item in self.connectors}
        specialties = {item.specialty_id: item for item in self.specialties}
        bundles = {item.role: item for item in self.core_bundles}
        for original, indexed in (
            (self.tools, tools),
            (self.connectors, connectors),
            (self.specialties, specialties),
            (self.core_bundles, bundles),
        ):
            if len(original) != len(indexed):
                raise ValueError("catalog IDs must be unique")
        if set(bundles) != CORE_ROLES:
            raise ValueError("catalog must define exactly the eight core bundles")
        for tool in self.tools:
            if tool.availability == "available":
                raise ValueError("contract-only catalog cannot enable tools")
            if not set(tool.connector_ids) <= connectors.keys():
                raise ValueError("unknown tool connector")
            for connector_id in tool.connector_ids:
                connector = connectors[connector_id]
                if tool.tool_id not in connector.capabilities:
                    raise ValueError("connector does not declare tool capability")
                if (
                    connector.egress == "policy_required"
                    and tool.egress != "policy_required"
                ):
                    raise ValueError("external connector requires tool egress policy")
            if tool.release == "future" and set(tool.permitted_roles) & CORE_ROLES:
                raise ValueError("future tools cannot grant core roles")
            if not set(tool.permitted_roles) <= CORE_ROLES | specialties.keys():
                raise ValueError("unknown role grant")
        for connector in self.connectors:
            if connector.availability == "available":
                raise ValueError("contract-only catalog cannot enable connectors")
            if not set(connector.capabilities) <= tools.keys():
                raise ValueError("unknown connector capability")
        for specialty in self.specialties:
            if not set(specialty.tool_ids) <= tools.keys():
                raise ValueError("specialty references unknown tools")
            if specialty.core_role is None and specialty.availability != "planned":
                raise ValueError("future specialties must remain planned")
        for bundle in self.core_bundles:
            if not set(bundle.tool_ids) <= tools.keys():
                raise ValueError("bundle references unknown tools")
            for tool_id in bundle.tool_ids:
                tool = tools[tool_id]
                if tool.release != "1.0" or bundle.role not in tool.permitted_roles:
                    raise ValueError("bundle requires explicit v1 role grant")
                if tool.effect == "dispatch":
                    raise ValueError("specialist bundles cannot dispatch effects")
        return self


def load_catalog() -> ToolkitCatalog:
    """Read packaged JSON fragments without importing any provider/handler."""
    combined: dict[str, list[object]] = {
        key: [] for key in ("connectors", "tools", "specialties", "core_bundles")
    }
    for name in ("investigation_catalog.json", "response_catalog.json"):
        fragment = json.loads(
            files("terminus.toolkit").joinpath(name).read_text(encoding="utf-8")
        )
        if set(fragment) != set(combined):
            raise ValueError("catalog fragment must contain exactly the four sections")
        for key, records in combined.items():
            records.extend(fragment[key])
    return ToolkitCatalog.model_validate_json(json.dumps(combined))
