"""Independently reconcile expired console responses without dispatch credentials."""

# ruff: noqa: INP001
import argparse
import asyncio
import json

from terminus.response.lab_observer import LabSSHObserver
from terminus.response.live import LiveResponseService
from terminus.storage.db import Database


class NoDispatch:
    async def dispatch(self, request: object) -> None:
        raise AssertionError("Read-only reconciliation cannot dispatch")


async def run(args: argparse.Namespace) -> None:
    db = Database(args.database)
    try:
        service = LiveResponseService(db)
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
