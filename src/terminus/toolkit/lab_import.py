"""Trusted local administrator import of bounded Wazuh authentication evidence."""

import hashlib
import json
from datetime import UTC, datetime

from pydantic import JsonValue

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.coordination_models import IncidentObjective
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.storage.db import Database
from terminus.toolkit.context import ReadResource, ToolReadPolicyStore
from terminus.toolkit.sources import ReadCollection, ReadObservation


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ValueError("Expected source object")
    return value


def import_authentication_incident(  # noqa: C901 -- ordered source admission
    db: Database,
    *,
    org_id: str,
    actor: str,
    agent_id: str,
    collection: ReadCollection,
) -> str:
    """Preserve provider records; grant reads only after current admin admission."""
    if (
        SqliteMembershipStore(db).role_of(OrgId(org_id), UserId(actor))
        != OrganizationRole.ADMIN
    ):
        raise ValueError("Current organization administrator required")
    if (
        collection.status != "ok"
        or collection.coverage != "complete"
        or collection.gaps
        or collection.truncated
        or not collection.observations
    ):
        raise ValueError("Import requires a successful nonempty bounded collection")
    sources: list[tuple[ReadObservation, dict[str, JsonValue]]] = []
    for observation in collection.observations:
        data = observation.data
        if observation.source_id != "wazuh-indexer" or not isinstance(data, dict):
            raise ValueError("Expected authenticated indexer evidence")
        alert = data.get("alert")
        if not isinstance(alert, dict) or not isinstance(alert.get("agent"), dict):
            raise ValueError("Missing endpoint identity")
        if _object(alert["agent"]).get("id") != agent_id:
            raise ValueError("Foreign endpoint evidence")
        rule = alert.get("rule")
        groups = rule.get("groups") if isinstance(rule, dict) else None
        if (
            not isinstance(rule, dict)
            or not isinstance(groups, list)
            or "authentication_failed" not in groups
        ):
            raise ValueError("Expected failed authentication evidence")
        if not isinstance(alert.get("id"), str) or not isinstance(
            alert.get("timestamp"), str
        ):
            raise ValueError("Missing source identity or timestamp")
        sources.append((observation, alert))
    sources.sort(key=lambda item: (item[0].source_timestamp, item[0].source_event_id))
    identity = json.dumps(
        [org_id, agent_id, sorted(item[0].source_event_id for item in sources)]
    )
    incident_id = "TICK-WAZUH-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
    latest = sources[-1][1]
    now = datetime.now(UTC).isoformat()
    policies = ToolReadPolicyStore(db)
    coordination = CoordinationService(db)
    with db.transaction():
        if db.fetchone(
            "SELECT 1 FROM incidents WHERE ticket_id=? AND org_id=?",
            (incident_id, org_id),
        ):
            return incident_id  # replay never expands grants or reschedules
        _ = db.execute(
            """INSERT INTO incidents(ticket_id,org_id,alert_id,rule_id,rule_description,
            severity,confidence,summary,recommended_actions,agent_name,full_log,
            policy_tier,status,created_at,updated_at,raw_payload_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                incident_id,
                org_id,
                latest["id"],
                str(_object(latest["rule"])["id"]),
                _object(latest["rule"]).get("description", ""),
                "low",
                "low",
                "Imported authentication events; investigation pending. Severity is provisional.",
                "[]",
                _object(latest["agent"]).get("name", ""),
                latest.get("full_log", ""),
                "triage",
                "OPEN",
                now,
                now,
                json.dumps(latest),
            ),
        )
        policy = policies.put_policy(
            actor,
            org_id,
            incident_id,
            {
                "triage": ("incident.get", "alerts.search", "collection.coverage"),
            },
            ("terminus_store", "wazuh_manager", "wazuh_indexer"),
        )
        for resource, kind, endpoint in (
            ("incident-ref", "incident", None),
            ("endpoint-ref", "endpoint", agent_id),
        ):
            policy = policies.bind_resource(
                actor,
                ReadResource.model_validate(
                    {
                        "resource_id": resource,
                        "org_id": org_id,
                        "incident_id": incident_id,
                        "kind": kind,
                        "agent_id": endpoint,
                    }
                ),
                expected_version=policy.version,
            )
        root = coordination.start_incident(
            org_id,
            incident_id,
            IncidentObjective(
                objective="Collect real authentication evidence and endpoint coverage; no model or response actions.",
                areas=["alert_handling"],
                idempotency_key="wazuh-lab-import",
            ),
        )
        for observation, _ in sources:
            _ = coordination.records.create_evidence(
                org_id,
                root.task_id,
                "source.wazuh_import",
                observation.source_timestamp,
                content=observation.model_dump(mode="json"),
            )
    return incident_id
