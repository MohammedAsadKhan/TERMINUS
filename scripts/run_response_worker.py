"""Opt-in console response worker. Credentials remain local; no standalone dispatcher."""

# ruff: noqa: INP001
import argparse
import asyncio
import getpass
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from pydantic import SecretStr

from terminus.response.lab_observer import LabSSHObserver
from terminus.response.live import LiveResponseService
from terminus.response.wazuh_transport import WazuhResponseTransport
from terminus.storage.db import Database
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.sources import EndpointResource
from terminus.toolkit.wazuh_readers import (
    WazuhIndexerReader,
    WazuhIndexerSettings,
    WazuhManagerReader,
    WazuhManagerSettings,
)


async def run(args: argparse.Namespace) -> None:
    settings = WazuhManagerSettings(
        org_id=args.org,
        manager_url="https://192.168.56.104:55000",
        username=SecretStr(
            (await asyncio.to_thread(input, "Response API username: ")).strip()
        ),
        password=SecretStr(getpass.getpass("Response API password: ")),
        verify_tls=False,
    )
    transport = WazuhResponseTransport(
        settings, allowed_agent_id="001", allowed_source_ip=IPv4Address("10.77.0.10")
    )
    manager = WazuhManagerReader(settings)
    indexer = WazuhIndexerReader(
        WazuhIndexerSettings(
            org_id=args.org,
            indexer_url="https://127.0.0.1:19200",
            username=SecretStr("admin"),
            password=SecretStr(getpass.getpass("Indexer password (admin): ")),
            verify_tls=False,
        )
    )
    db = Database(args.database)
    service = LiveResponseService(db)
    observer = LabSSHObserver(args.kali_management_ip)
    try:
        service.require_admin(args.org, args.actor)
        if not await observer("baseline", {}):
            raise ValueError("Independent lab baseline unavailable")
        print(
            "Console response worker ready; waiting for incident approval/autonomy. No action authorized by startup.",
            flush=True,
        )
        while True:
            now = datetime.now(UTC)
            context = await manager.read(
                ReadQuery(
                    resource_id="response-target",
                    start=now - timedelta(minutes=2),
                    end=now + timedelta(seconds=5),
                    event_kind="inventory",
                ),
                EndpointResource(
                    org_id=args.org, resource_id="response-target", agent_id="001"
                ),
            )
            if context.status == "ok" and any(
                isinstance(o.data, dict)
                and o.data.get("connectivity") == "active"
                and o.data.get("name") == "terminus-target-a"
                for o in context.observations
            ):
                collection = await indexer.read(
                    ReadQuery(
                        resource_id="response-target",
                        start=now - timedelta(seconds=120),
                        end=now,
                        event_kind="authentication",
                    ),
                    EndpointResource(
                        org_id=args.org, resource_id="response-target", agent_id="001"
                    ),
                )
                service.ingest(args.org, args.actor, collection)
                await service.tick(
                    args.org,
                    transport,
                    observer,
                    available=collection.status in {"ok", "empty"}
                    and collection.coverage == "complete"
                    and not collection.gaps
                    and not collection.truncated,
                )
            else:
                await service.tick(args.org, transport, observer, available=False)
                print("Manager unavailable; new dispatch paused.", flush=True)
            await asyncio.sleep(5)
    finally:
        db.execute("DELETE FROM live_response_runtime WHERE org_id=?", (args.org,))
        await manager.aclose()
        await indexer.aclose()
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "kali-management-ip"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None
