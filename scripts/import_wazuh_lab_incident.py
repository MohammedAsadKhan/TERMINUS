"""Import one explicitly scoped real lab incident and queue read-only triage."""
# ruff: noqa: INP001 -- standalone administrator script

import argparse
import asyncio
import getpass
from datetime import UTC, datetime, timedelta

from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.storage.db import Database
from terminus.toolkit.lab_import import import_authentication_incident
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.sources import EndpointResource, ReadCollection, ReadObservation
from terminus.toolkit.wazuh_deployment import readers_from_environ


class Arguments(argparse.Namespace):
    database: str = ""
    org: str = ""
    actor: str = ""
    start: str = ""
    end: str = ""
    agent: str = "001"
    source: str = "10.77.0.10"


def matches(item: ReadObservation, source: str) -> bool:
    data = item.data
    alert = data.get("alert") if isinstance(data, dict) else None
    if not isinstance(alert, dict):
        return False
    context, rule = alert.get("data"), alert.get("rule")
    groups = rule.get("groups") if isinstance(rule, dict) else None
    return (
        isinstance(context, dict)
        and context.get("srcip") == source
        and isinstance(groups, list)
        and "authentication_failed" in groups
    )


async def run(args: Arguments) -> None:
    db = Database(args.database)
    manager = indexer = None
    try:
        if (
            SqliteMembershipStore(db).role_of(OrgId(args.org), UserId(args.actor))
            != OrganizationRole.ADMIN
        ):
            raise ValueError("Current organization administrator required")
        query = ReadQuery(
            resource_id="endpoint-ref",
            start=datetime.fromisoformat(args.start),
            end=datetime.fromisoformat(args.end),
            event_kind="authentication",
        )
        if query.start.tzinfo is None or query.end.tzinfo is None:
            raise ValueError("Supply timestamps with timezone offsets")
        prefix = "TERMINUS_SPECIALIST_WAZUH_"
        env = {
            "TERMINUS_DEPLOYMENT_MODE": "local",
            prefix + "ORG_ID": args.org,
            prefix + "VERIFY_TLS": "false",
            prefix + "MANAGER_URL": "https://192.168.56.104:55000",
            prefix + "MANAGER_USER": "wazuh-wui",
            prefix + "MANAGER_PASSWORD": getpass.getpass(
                "Manager password (wazuh-wui): "
            ),
            prefix + "INDEXER_URL": "https://127.0.0.1:19200",
            prefix + "INDEXER_USER": "admin",
            prefix + "INDEXER_PASSWORD": getpass.getpass("Indexer password (admin): "),
        }
        manager, indexer = readers_from_environ(env, args.org)
        if manager is None or indexer is None:
            raise ValueError("Both readers are required")
        endpoint = EndpointResource(
            org_id=args.org, resource_id="endpoint-ref", agent_id=args.agent
        )
        # Manager inventory is a current snapshot, not historical telemetry.
        now = datetime.now(UTC)
        inventory_query = ReadQuery(
            resource_id="endpoint-ref",
            start=now - timedelta(minutes=55),
            end=now + timedelta(minutes=5),
            event_kind="inventory",
        )
        context = await manager.read(inventory_query, endpoint)
        if context.status != "ok" or not context.observations:
            raise ValueError("Manager endpoint read failed: " + "; ".join(context.gaps))
        collection = await indexer.read(query, endpoint)
        if collection.status != "ok":
            raise ValueError("Indexer read failed: " + "; ".join(collection.gaps))
        selected = tuple(
            item for item in collection.observations if matches(item, args.source)
        )
        incident = import_authentication_incident(
            db,
            org_id=args.org,
            actor=args.actor,
            agent_id=args.agent,
            collection=ReadCollection(
                status="ok", observations=selected, coverage=collection.coverage
            ),
        )
        print(
            f"Imported {len(selected)} real events. Incident: {incident}. Read-only triage queued (or existing import retained)."
        )
    finally:
        if manager is not None:
            await manager.aclose()
        if indexer is not None:
            await indexer.aclose()
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "start", "end"):
        _ = parser.add_argument("--" + name, required=True)
    _ = parser.add_argument("--agent", default="001")
    _ = parser.add_argument("--source", default="10.77.0.10")
    try:
        asyncio.run(run(parser.parse_args(namespace=Arguments())))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
