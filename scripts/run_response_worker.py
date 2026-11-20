# File name: run_response_worker.py
# Author: Team LARP
# Revision date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Opt-in console response worker. Credentials remain local; no standalone dispatcher.

"""Opt-in console response worker. Credentials remain local; no standalone dispatcher."""

# ruff: noqa: INP001
import argparse
import asyncio
import getpass
import os
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

from pydantic import SecretStr

from terminus.response.docker_lab_observer import DockerLabObserver
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
    """Run the console response worker loop until it is interrupted.

    Startup authorizes no action: the worker only polls, and a response can be sent only
    after an incident approval or an autonomy policy elsewhere in the service. Credentials
    come from the environment or a local prompt and are never command-line arguments.
    """
    manager_url = getattr(args, "manager_url", "https://192.168.56.104:55000")
    indexer_url = getattr(args, "indexer_url", "https://127.0.0.1:19200")
    observer_mode = getattr(args, "observer", "ssh")
    agent_id = getattr(args, "agent_id", "001")
    verify_tls = _verify_tls(args, manager_url, indexer_url, observer_mode)
    # Environment variables take precedence so a scripted run needs no prompt.
    api_user = (
        os.environ.get("TERMINUS_RESPONSE_API_USER")
        or (await asyncio.to_thread(input, "Response API username: ")).strip()
    )
    api_password = os.environ.get("TERMINUS_RESPONSE_API_PASSWORD") or getpass.getpass(
        "Response API password: "
    )
    indexer_password = os.environ.get(
        "TERMINUS_RESPONSE_INDEXER_PASSWORD"
    ) or getpass.getpass("Indexer password (admin): ")
    settings = WazuhManagerSettings(
        org_id=args.org,
        manager_url=manager_url,
        username=SecretStr(api_user),
        password=SecretStr(api_password),
        verify_tls=verify_tls,
    )
    transport = WazuhResponseTransport(
        settings, allowed_agent_id=agent_id, allowed_source_ip=IPv4Address("10.77.0.10")
    )
    manager = WazuhManagerReader(settings)
    indexer = WazuhIndexerReader(
        WazuhIndexerSettings(
            org_id=args.org,
            indexer_url=indexer_url,
            username=SecretStr("admin"),
            password=SecretStr(indexer_password),
            verify_tls=verify_tls,
        )
    )
    # The worker must act on the same agent the API bound responses to; a mismatch would
    # let a response be proposed for one agent and sent for another.
    if os.environ.get("TERMINUS_RESPONSE_AGENT_ID", agent_id) != agent_id:
        raise ValueError("Worker agent ID differs from the API response binding")
    os.environ["TERMINUS_RESPONSE_AGENT_ID"] = agent_id
    db = Database(args.database)
    service = LiveResponseService(db)
    # Recovery is confirmed by an observer independent of the Wazuh API that sent the
    # command, either the disposable Docker lab or SSH to the lab host.
    if observer_mode == "docker":
        observer = DockerLabObserver(local_script=True)
    elif args.kali_management_ip:
        observer = LabSSHObserver(args.kali_management_ip)
    else:
        raise ValueError("SSH observer requires --kali-management-ip")
    try:
        # Authorization first, then an independent baseline; with no baseline the worker
        # refuses to start because recovery could not be verified later.
        service.require_admin(args.org, args.actor)
        if not await observer("baseline", {}):
            raise ValueError("Independent lab baseline unavailable")
        print(
            "Console response worker ready; waiting for incident approval/autonomy. No action authorized by startup.",
            flush=True,
        )
        while True:
            try:
                await _worker_cycle(
                    args, manager, indexer, service, transport, observer, agent_id
                )
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower():
                    raise
                # Another process can briefly hold SQLite's writer lock. Keep the
                # durable intent for reconciliation instead of losing the worker.
                print("Database busy; response cycle will retry.", flush=True)
            await asyncio.sleep(5)
    finally:
        # Drop this organization's runtime record on exit so a stopped worker is not left
        # registered; a locked database is tolerated here rather than masking the exit.
        with suppress(sqlite3.OperationalError):
            db.execute("DELETE FROM live_response_runtime WHERE org_id=?", (args.org,))
        await manager.aclose()
        await indexer.aclose()
        db.close()


def _verify_tls(
    args: argparse.Namespace, manager_url: str, indexer_url: str, observer_mode: str
) -> bool:
    """Return whether TLS certificates are verified; skipping needs the fixed Docker lab."""
    if not getattr(args, "insecure_lab_tls", False):
        return True
    # Test certificates in the disposable Compose lab are not trusted by the
    # worker container. Limit this exception to its fixed private endpoints.
    if (
        observer_mode != "docker"
        or manager_url != "https://wazuh.manager:55000"
        or indexer_url != "https://wazuh.indexer:9200"
    ):
        raise ValueError(
            "--insecure-lab-tls requires the disposable Docker observer and fixed Wazuh lab URLs"
        )
    return False


async def _worker_cycle(
    args: argparse.Namespace,
    manager: WazuhManagerReader,
    indexer: WazuhIndexerReader,
    service: LiveResponseService,
    transport: WazuhResponseTransport,
    observer: Callable[[str, dict[str, Any]], Awaitable[bool]],
    agent_id: str,
) -> None:
    """Run one poll cycle: read agent status and recent failures, then advance responses.

    New dispatch is allowed only after a complete, untruncated read. Recovery observation
    still runs when the manager or the read is unavailable, so expired effects are checked.
    """
    now = datetime.now(UTC)
    # Only dispatch while the manager reports the named lab agent as active.
    context = await manager.read(
        ReadQuery(
            resource_id="response-target",
            start=now - timedelta(minutes=2),
            end=now + timedelta(seconds=5),
            event_kind="inventory",
        ),
        EndpointResource(
            org_id=args.org, resource_id="response-target", agent_id=agent_id
        ),
    )
    if context.status == "ok" and any(
        isinstance(o.data, dict)
        and o.data.get("connectivity") == "active"
        and o.data.get("name") == "terminus-target-a"
        for o in context.observations
    ):
        # Bounded window and page count keep each cycle small.
        collection = await indexer.read(
            ReadQuery(
                resource_id="response-target",
                start=now - timedelta(seconds=120),
                end=now,
                event_kind="authentication_failure",
                page_size=20,
                max_pages=2,
            ),
            EndpointResource(
                org_id=args.org, resource_id="response-target", agent_id=agent_id
            ),
        )
        service.ingest(args.org, args.actor, collection)
        # A partial, gapped, or truncated read pauses new dispatch (available is False)
        # rather than being treated as an absence of attacks.
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
        # Manager state unknown: pause new dispatch but still let recovery run.
        await service.tick(args.org, transport, observer, available=False)
        print("Manager unavailable; new dispatch paused.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--manager-url", default="https://192.168.56.104:55000")
    parser.add_argument("--indexer-url", default="https://127.0.0.1:19200")
    parser.add_argument("--observer", choices=("ssh", "docker"), default="ssh")
    parser.add_argument("--kali-management-ip", default="")
    parser.add_argument("--agent-id", default="001")
    parser.add_argument(
        "--insecure-lab-tls",
        action="store_true",
        help="Accept the disposable Docker lab's self-signed Wazuh certificates",
    )
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None
