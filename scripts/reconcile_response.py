# File name: reconcile_response.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Independently reconcile expired console responses without dispatch credentials.

"""Independently reconcile expired console responses without dispatch credentials."""

# ruff: noqa: INP001
import argparse
import asyncio
import json

from terminus.response.lab_observer import LabSSHObserver
from terminus.response.live import LiveResponseService
from terminus.storage.db import Database


class NoDispatch:
    """Transport stand-in that fails loudly if reconciliation ever tries to send."""

    async def dispatch(self, request: object) -> None:
        """Refuse every dispatch so this script cannot trigger or renew a response."""
        raise AssertionError("Read-only reconciliation cannot dispatch")


async def run(args: argparse.Namespace) -> None:
    """Run one recovery pass over expired console responses and print every intent's state.

    The service is run with ``available=False``, so it does not take over the response
    runtime and only observes recovery through the independent SSH observer.
    """
    db = Database(args.database)
    try:
        service = LiveResponseService(db)
        # Authorization first: only a current organization administrator may reconcile.
        service.require_admin(args.org, args.actor)
        await service.tick(
            args.org,
            NoDispatch(),
            LabSSHObserver(args.kali_management_ip),
            available=False,
        )
        print(
            json.dumps(
                db.fetchall(
                    "SELECT incident_id,intent_id,state FROM live_response_intents WHERE org_id=?",
                    (args.org,),
                ),
                indent=2,
            )
        )
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "kali-management-ip"):
        parser.add_argument("--" + name, required=True)
    asyncio.run(run(parser.parse_args()))
