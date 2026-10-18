"""Opt in once to bounded autonomous SSH blocking in the isolated lab."""
# ruff: noqa: INP001
import argparse
import asyncio
import getpass
import os
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pydantic import SecretStr

from terminus.response.autonomous_lab import (
    AutonomousLabController,
    LabAutonomousPolicy,
)
from terminus.response.lab_observer import LabSSHObserver
from terminus.response.wazuh_transport import WazuhResponseTransport
from terminus.storage.db import Database
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.sources import EndpointResource
from terminus.toolkit.wazuh_deployment import readers_from_environ
from terminus.toolkit.wazuh_readers import WazuhManagerSettings


async def run(args: argparse.Namespace) -> None:
    db = Database(args.database)
    prefix = "TERMINUS_SPECIALIST_WAZUH_"
    manager_password = getpass.getpass("Manager read password (wazuh-wui): ")
    indexer_password = getpass.getpass("Indexer password (admin): ")
    print("Response API username (restricted to agent 001): ", end="", file=sys.stderr, flush=True)
    response_user = (await asyncio.to_thread(input)).strip()
    response_password = getpass.getpass("Response API password: ")
    env = {"TERMINUS_DEPLOYMENT_MODE": "local", prefix + "ORG_ID": args.org,
           prefix + "VERIFY_TLS": "false", prefix + "MANAGER_URL": "https://192.168.56.104:55000",
           prefix + "MANAGER_USER": "wazuh-wui", prefix + "MANAGER_PASSWORD": manager_password,
           prefix + "INDEXER_URL": "https://127.0.0.1:19200", prefix + "INDEXER_USER": "admin",
           prefix + "INDEXER_PASSWORD": indexer_password}
    manager, indexer = readers_from_environ(env, args.org)
    if manager is None or indexer is None:
        raise ValueError("Both readers required")
    try:
        observer = LabSSHObserver(args.kali_management_ip)
        if not await observer("baseline", {}):
            raise ValueError("Baseline unavailable. Configure known-host SSH keys for both guests and read-only nft sudo access before enabling. No action taken.")
        transport = WazuhResponseTransport(WazuhManagerSettings(org_id=args.org, manager_url="https://192.168.56.104:55000", username=SecretStr(response_user), password=SecretStr(response_password), verify_tls=False), allowed_agent_id="001", allowed_source_ip=IPv4Address("10.77.0.10"))
        controller = AutonomousLabController(db, transport, observer)
        policy = LabAutonomousPolicy(org_id=args.org, actor_id=args.actor, enabled_until=datetime.now(UTC) + timedelta(minutes=30))
        controller.enable(policy)
        print(f"Controller process PID: {os.getpid()}", flush=True)
        print("Autonomous LAB policy enabled for 30 minutes: 3 fresh failures / 120s; agent 001; Kali only; 60s block; 300s cooldown; at most 3 actions. No model calls.", flush=True)
        endpoint = EndpointResource(org_id=args.org, resource_id="autonomous-lab-target", agent_id="001")
        while datetime.now(UTC) < policy.enabled_until:
            now = datetime.now(UTC)
            query = ReadQuery(resource_id=endpoint.resource_id, start=now - timedelta(seconds=120), end=now, event_kind="authentication")
            context = await manager.read(ReadQuery(resource_id=endpoint.resource_id, start=now - timedelta(minutes=2), end=now + timedelta(seconds=5), event_kind="inventory"), endpoint)
            if context.status == "ok" and any(isinstance(item.data, dict) and item.data.get("connectivity") == "active" and item.data.get("name") == "terminus-target-a" for item in context.observations):
                result = await controller.process(args.org, await indexer.read(query, endpoint))
                print("Policy evaluation: " + result, flush=True)
                if result in {"unknown", "reconciliation_required", "quota_exhausted"}:
                    break
            else:
                print("Manager endpoint context unavailable; no action.", flush=True)
            await asyncio.sleep(5)
    finally:
        await manager.aclose()
        await indexer.aclose()
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "kali-management-ip"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--enable-autonomous-lab", action="store_true", required=True)
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
