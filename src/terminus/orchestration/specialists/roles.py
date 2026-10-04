"""Fixed, ordered read plans for the eight core specialist roles.

Every plan is code: tool ids come from the role's catalog bundle, and every
query is derived from the leased task alone (never from model output). Resource
references follow a deployment convention an administrator binds per incident
(`bind_resource`): ``incident-ref`` for the incident and ``endpoint-ref`` for
its endpoint. An unbound reference is denied by the gateway and surfaces as an
explicit gap, never as a finding.

Tools that are catalog-only today (network, application, reporting, ...) stay in
the plans so their absence is reported as ``tool_not_installed``. No plan
contains a dispatch or proposal tool: ``response.wazuh_ip_block`` and
``recovery.wazuh_ip_unblock`` are granted to nobody, and ``response.propose`` is
deliberately omitted until proposals are built (A03).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Final

from terminus.orchestration.models import Task
from terminus.orchestration.specialists.runtime import PlannedCall, RoleSpec
from terminus.toolkit.models import ReadQuery

INCIDENT_RESOURCE_ID: Final = "incident-ref"
ENDPOINT_RESOURCE_ID: Final = "endpoint-ref"
_BEFORE = timedelta(minutes=55)
_AFTER = timedelta(minutes=5)  # total window is exactly the one-hour read limit


def _query(task: Task, resource_id: str, kind: str) -> ReadQuery:
    """Window anchored on the lease's claim time (task creation if unclaimed)."""
    anchor = task.started_at or task.created_at
    return ReadQuery.model_validate(
        {
            "resource_id": resource_id,
            "start": anchor - _BEFORE,
            "end": anchor + _AFTER,
            "event_kind": kind,
        }
    )


def _call(
    tool_id: str, resource_id: str, kind: str = "evidence", *, cite: bool = False
) -> PlannedCall:
    return PlannedCall(
        tool_id,
        lambda task: _query(task, resource_id, kind),
        cite_run_evidence=cite,
    )


def _incident(tool_id: str, *, cite: bool = False) -> PlannedCall:
    return _call(tool_id, INCIDENT_RESOURCE_ID, cite=cite)


def _endpoint(tool_id: str, kind: str = "evidence") -> PlannedCall:
    return _call(tool_id, ENDPOINT_RESOURCE_ID, kind)


_INCIDENT_GET = _incident("incident.get")
_ALERTS = _endpoint("alerts.search")
_COVERAGE = _endpoint("collection.coverage")

ROLE_SPECS: Final[dict[str, RoleSpec]] = {
    "triage": RoleSpec("triage", (_INCIDENT_GET, _ALERTS, _COVERAGE)),
    "identity": RoleSpec(
        "identity", (_INCIDENT_GET, _endpoint("identity.auth_events"), _COVERAGE)
    ),
    "endpoint": RoleSpec(
        "endpoint", (_INCIDENT_GET, _endpoint("endpoint.agent"), _ALERTS, _COVERAGE)
    ),
    "network": RoleSpec(
        "network",
        (
            _INCIDENT_GET,
            _ALERTS,
            _COVERAGE,
            _endpoint("network.connections", "network"),
            _endpoint("network.dns", "network"),
        ),
    ),
    "application_api": RoleSpec(
        "application_api",
        (
            _INCIDENT_GET,
            _ALERTS,
            _COVERAGE,
            _endpoint("application.requests", "application"),
            _endpoint("application.inventory", "application"),
        ),
    ),
    "response_planner": RoleSpec(
        "response_planner",
        (
            _incident("evidence.timeline"),
            _incident("evidence.validate_citations", cite=True),
            _incident("response.eligibility"),
        ),
    ),
    "verification": RoleSpec(
        "verification",
        (
            _incident("evidence.timeline"),
            _incident("evidence.validate_citations", cite=True),
            _incident("verification.evaluate"),
        ),
    ),
    "evidence_reporting": RoleSpec(
        "evidence_reporting",
        (
            _incident("evidence.timeline"),
            _incident("evidence.validate_citations", cite=True),
            _incident("reporting.incident_draft"),
        ),
    ),
}
