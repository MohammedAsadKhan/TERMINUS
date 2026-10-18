"""Reconcile expired autonomous lab actions using independent SSH observations only."""
# ruff: noqa: INP001
import argparse
import asyncio
import json

from terminus.response.autonomous_lab import reconcile_lab_actions
from terminus.response.lab_observer import LabSSHObserver
from terminus.storage.db import Database


async def run(args: argparse.Namespace) -> None:
    db = Database(args.database)
    try:
        results = await reconcile_lab_actions(db, args.org, args.actor, LabSSHObserver(args.kali_management_ip))
        print(json.dumps(results, indent=2))
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "kali-management-ip"):
        parser.add_argument("--" + name, required=True)
    try:
        asyncio.run(run(parser.parse_args()))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
