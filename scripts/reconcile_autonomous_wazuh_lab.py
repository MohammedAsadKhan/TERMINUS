# File name: reconcile_autonomous_wazuh_lab.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Reconcile expired autonomous lab actions using independent SSH observations only.

"""Reconcile expired autonomous lab actions using independent SSH observations only."""
# ruff: noqa: INP001
import argparse
import asyncio
import json

from terminus.response.autonomous_lab import reconcile_lab_actions
from terminus.response.lab_observer import LabSSHObserver
from terminus.storage.db import Database


async def run(args: argparse.Namespace) -> None:
    """Observe expired autonomous lab actions and print each action's reconciled state.

    The check uses an independent SSH observer for the lab host and never sends or renews
    an action. An action that cannot be observed is reported as unresolved, not recovered.
    """
    db = Database(args.database)
    try:
        results = await reconcile_lab_actions(db, args.org, args.actor, LabSSHObserver(args.kali_management_ip))
        print(json.dumps(results, indent=2))
    finally:
        db.close()


def main() -> None:
    """Parse arguments and run reconciliation, exiting with the error text on a refusal."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "kali-management-ip"):
        parser.add_argument("--" + name, required=True)
    try:
        asyncio.run(run(parser.parse_args()))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
