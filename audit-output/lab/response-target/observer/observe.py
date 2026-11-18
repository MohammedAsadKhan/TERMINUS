#!/usr/bin/env python3
# File: observe.py
# Author: Team LARP
# Revision date: 2026-11-12
# Version: 0.1.0
# Purpose: Independent SSH and nftables observations for the Docker response target.
"""Independent SSH and nftables observations for the Docker response target.

The observer never executes commands inside the target container. It reaches
the target and attacker over their management addresses on single-node_default
and asks the attacker to probe the attack-path address. This keeps the source
denial, management health, and owned nftables membership checks independent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime

KEY = "/tmp/lab_ed25519"
KNOWN_HOSTS = "/run/lab-keys/known_hosts"
TARGET_MGMT = "target"
ATTACKER_MGMT = "attacker"
TARGET_ATTACK = "10.77.0.20"
SOURCE_IP = "10.77.0.10"
TARGET_HOSTNAME = "terminus-target-a"
SSH_TIMEOUT = 8


def ssh(user: str, host: str, command: str) -> tuple[int, str]:
    """Run one bounded SSH command with pinned host keys and no password prompt."""
    args = [
        "ssh",
        "-i",
        KEY,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "ConnectTimeout=3",
        f"{user}@{host}",
        command,
    ]
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=SSH_TIMEOUT,
            check=False,
        )
        return completed.returncode, completed.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return 1, ""


def management_hostname() -> tuple[bool, str]:
    status, output = ssh("labadmin", TARGET_MGMT, "hostname")
    return status == 0 and output == TARGET_HOSTNAME, output


def attack_probe() -> tuple[bool, str, bool]:
    """Ask the attacker to probe the target. True means the port is reachable."""
    status, output = ssh(
        "probe",
        ATTACKER_MGMT,
        f"nc -z -w 2 {TARGET_ATTACK} 22; printf 'PROBE_STATUS:%s' $?",
    )
    if status != 0:
        return False, output, False
    if output == "PROBE_STATUS:0":
        return True, output, True
    if output == "PROBE_STATUS:1":
        return True, output, False
    return False, output, False


def read_nft_table(table: str) -> tuple[int, str]:
    return ssh(
        "labadmin",
        TARGET_MGMT,
        f"sudo -n /usr/sbin/nft --json list table inet {table}",
    )


def list_nft_tables() -> tuple[int, str]:
    return ssh("labadmin", TARGET_MGMT, "sudo -n /usr/sbin/nft --json list tables")


def owned_table_state(identity: str, table: str) -> dict[str, object]:
    status, output = read_nft_table(table)
    state: dict[str, object] = {
        "read_status": status,
        "table_present": False,
        "owned": False,
        "set_present": False,
        "source_element_present": False,
        "element_count": None,
    }
    if status != 0:
        return state
    try:
        records = json.loads(output).get("nftables", [])
    except (ValueError, AttributeError):
        state["read_status"] = "invalid-json"
        return state
    table_entry = next(
        (
            record["table"]
            for record in records
            if "table" in record
            and record["table"].get("family") == "inet"
            and record["table"].get("name") == table
        ),
        None,
    )
    if table_entry is None:
        return state
    state["table_present"] = True
    state["owned"] = table_entry.get("comment") == identity
    sets = [
        record["set"]
        for record in records
        if "set" in record
        and record["set"].get("name") == "blocked"
        and record["set"].get("table") == table
    ]
    if len(sets) != 1:
        return state
    state["set_present"] = True
    elements = sets[0].get("elem", [])
    state["element_count"] = len(elements)
    state["source_element_present"] = any(
        element == SOURCE_IP
        or (
            isinstance(element, dict)
            and isinstance(element.get("elem"), dict)
            and element["elem"].get("val") == SOURCE_IP
        )
        for element in elements
    )
    return state


def identity_table(intent: str, digest: str) -> tuple[str, str]:
    identity = hashlib.sha256(f"{intent}:{digest}".encode()).hexdigest()
    return identity, "terminus_" + identity[:24]


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent response-target observations")
    parser.add_argument(
        "--stage",
        required=True,
        choices=("baseline", "blocked", "recovered", "table-absent"),
    )
    parser.add_argument("--intent", default="")
    parser.add_argument("--digest", default="")
    args = parser.parse_args()

    identity = table = None
    if args.stage != "baseline":
        if not args.intent or not args.digest:
            parser.error("--intent and --digest are required after baseline")
        identity, table = identity_table(args.intent, args.digest)

    checks: dict[str, bool] = {}
    details: dict[str, object] = {
        "stage": args.stage,
        "target_management": TARGET_MGMT,
        "attacker_management": ATTACKER_MGMT,
        "target_attack": TARGET_ATTACK,
        "source": SOURCE_IP,
        "intent": args.intent or None,
        "digest": args.digest or None,
        "identity": identity,
        "table": table,
    }

    management_ok, hostname = management_hostname()
    checks["management_ssh"] = management_ok
    details["management_hostname"] = hostname

    probe_reached, probe_output, reachable = attack_probe()
    details["attack_probe_output"] = probe_output

    if args.stage == "baseline":
        checks["observer_can_probe_attacker"] = probe_reached
        checks["attack_path_reachable"] = probe_reached and reachable
        nft_status, _ = list_nft_tables()
        checks["nft_readable"] = nft_status == 0
    elif args.stage == "blocked":
        checks["observer_can_probe_attacker"] = probe_reached
        checks["attack_path_denied"] = probe_reached and not reachable
        state = owned_table_state(identity or "", table or "")
        details["nft"] = state
        checks["owned_table"] = (
            state["table_present"] is True and state["owned"] is True
        )
        checks["owned_set"] = state["set_present"] is True
        checks["source_element_present"] = (
            state["source_element_present"] is True
        )
    elif args.stage == "recovered":
        checks["observer_can_probe_attacker"] = probe_reached
        checks["attack_path_reachable"] = probe_reached and reachable
        state = owned_table_state(identity or "", table or "")
        details["nft"] = state
        checks["owned_table"] = (
            state["table_present"] is True and state["owned"] is True
        )
        checks["owned_set_empty"] = (
            state["set_present"] is True and state["element_count"] == 0
        )
    else:
        checks["observer_can_probe_attacker"] = probe_reached
        checks["attack_path_reachable"] = probe_reached and reachable
        nft_status, output = read_nft_table(table or "")
        table_present = nft_status == 0 and f'"{table}"' in output
        details["table_read_status"] = nft_status
        details["table_present"] = table_present
        checks["owned_table_absent"] = not table_present

    details["checks"] = checks
    details["verified"] = all(checks.values())
    details["observed_at"] = datetime.now(UTC).isoformat()
    print(json.dumps(details, indent=2, sort_keys=True))
    return 0 if details["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
