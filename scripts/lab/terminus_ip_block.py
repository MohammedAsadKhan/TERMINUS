#!/usr/bin/python3
# File name: terminus_ip_block.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Wazuh endpoint command for the isolated Scenario A lab only.

"""Wazuh endpoint command for the isolated Scenario A lab only.

Install root-owned on terminus-target-a. No model arguments, shell, arbitrary
targets or credentials. nftables expires the blocked set element independently
of the Windows worker. A bounded maintenance pass removes only empty owned tables.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any

NFT = "/usr/sbin/nft"
SOURCE = "10.77.0.10"
MAX_INPUT = 8192
MAX_OBSERVATION = 65536
MAX_CLEANUP_TABLES = 64
OWNED_TABLE = re.compile(r"terminus_[a-f0-9]{24}\Z")
IDENTITY = re.compile(r"[a-f0-9]{64}\Z")


def log_status(state: str) -> None:
    """Append a short outcome line to the Wazuh active-response log, ignoring write errors."""
    # Wazuh's API acknowledges delivery before this endpoint runs. A bounded
    # local line makes endpoint failures diagnosable without logging alert data.
    with (
        suppress(OSError),
        Path("/var/ossec/logs/active-responses.log").open("a", encoding="utf-8") as log,
    ):
        log.write(f"terminus-ip-block: {state[:160]}\n")


def plan(message: dict) -> tuple[str, str, str, int]:
    """Validate a Wazuh message and derive the command, table name, identity, and duration.

    Every field is checked before any nft call because the message crosses a trust
    boundary. The table name comes from a hash of the intent and proposal digest, so a table
    can be found again only by the same approved action.
    """
    if message.get("command") not in {"add", "delete"}:
        raise ValueError("Unsupported command")
    data = message["parameters"]["alert"]["data"]
    if data.get("srcip") != SOURCE:
        raise ValueError("Only the configured lab source is permitted")
    intent = data.get("terminus_intent_id")
    digest = data.get("terminus_proposal_digest")
    duration = data.get("terminus_duration_seconds")
    if not isinstance(intent, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", intent
    ):
        raise ValueError("Invalid intent")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Invalid digest")
    if type(duration) is not int or not 30 <= duration <= 900:
        raise ValueError("Invalid duration")
    identity = hashlib.sha256(f"{intent}:{digest}".encode()).hexdigest()
    return message["command"], f"terminus_{identity[:24]}", identity, duration


def batch(table: str, identity: str, duration: int) -> str:
    """Build the nft batch: an owned table whose set element expires on its own timer."""
    return (
        f'add table inet {table} {{ comment "{identity}"; }}\n'
        f"add set inet {table} blocked {{ type ipv4_addr; flags timeout; }}\n"
        f"add element inet {table} blocked {{ {SOURCE} timeout {duration}s }}\n"
        f"add chain inet {table} incoming {{ type filter hook input priority -10; policy accept; }}\n"
        f"add rule inet {table} incoming ip saddr @blocked drop\n"
    )


def execute(message: dict, runner: Callable[..., Any] = subprocess.run) -> dict:
    """Apply one add or delete and return its state; ``verified`` is always False here.

    A successful nft exit status only means the command was accepted. Independent
    verification of the block or its recovery is done by the observer outside this script.
    """
    command, table, identity, duration = plan(message)
    observed = runner(
        [NFT, "--json", "list", "table", "inet", table],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if observed.returncode == 0:
        if len(observed.stdout) > MAX_OBSERVATION:
            raise ValueError("Oversized ownership observation")
        records = json.loads(observed.stdout).get("nftables", [])
        owned = any(
            item.get("table", {}).get("name") == table
            and item.get("table", {}).get("comment") == identity
            and item.get("table", {}).get("family") == "inet"
            for item in records
        )
        if not owned:
            raise ValueError("Ownership mismatch")
        if command == "add":
            # A duplicate must not renew the TTL or recreate an expired effect.
            return {"state": "already_owned", "table": table, "verified": False}
        result = runner(
            [NFT, "delete", "table", "inet", table],
            capture_output=True,
            timeout=5,
            check=False,
        )
    elif command == "delete":
        # Nonzero list is ambiguous (missing, permission, provider failure).
        return {"state": "unknown", "table": table, "verified": False}
    else:
        # Atomic batch will fail rather than overwrite any existing table.
        result = runner(
            [NFT, "--file", "-"],
            input=batch(table, identity, duration).encode(),
            capture_output=True,
            timeout=5,
            check=False,
        )
    return {
        "state": "accepted" if result.returncode == 0 else "unknown",
        "table": table,
        "verified": False,
    }


def cleanup_expired(runner: Callable[..., Any] = subprocess.run) -> dict[str, object]:
    """Delete only bounded, empty tables whose full comment matches their name."""
    listed = runner(
        [NFT, "--json", "list", "tables"],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if listed.returncode != 0 or len(listed.stdout) > MAX_OBSERVATION:
        raise ValueError("Cannot bound table inventory")
    inventory = json.loads(listed.stdout)
    if not isinstance(inventory, dict):
        raise ValueError("Invalid table inventory")
    records = inventory.get("nftables", [])
    if not isinstance(records, list):
        raise ValueError("Invalid table inventory")
    candidates = [
        item["table"]["name"]
        for item in records
        if isinstance(item, dict)
        and isinstance(item.get("table"), dict)
        and item["table"].get("family") == "inet"
        and isinstance(item["table"].get("name"), str)
        and OWNED_TABLE.fullmatch(item["table"]["name"])
    ]
    if len(candidates) > MAX_CLEANUP_TABLES:
        raise ValueError("Too many owned table candidates")
    removed: list[str] = []
    for table in candidates:
        observed = runner(
            [NFT, "--json", "list", "table", "inet", table],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if observed.returncode != 0 or len(observed.stdout) > MAX_OBSERVATION:
            continue
        if not _expired_owned_table(table, observed.stdout):
            continue
        # The endpoint never renews an existing table. Once its only element
        # expires, no authorized path can add an element to this identity.
        result = runner(
            [NFT, "delete", "table", "inet", table],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            removed.append(table)
    return {"removed": removed, "verified": False}


def _expired_owned_table(table: str, payload: bytes) -> bool:  # noqa: PLR0911 -- fail closed at each malformed boundary
    """Return True only for an unmodified owned table whose blocked set is now empty.

    Any unexpected shape, extra object, or identity mismatch returns False so that the
    cleanup never deletes a table this script did not create.
    """
    try:
        records = json.loads(payload).get("nftables", [])
    except (ValueError, AttributeError):
        return False
    if not isinstance(records, list):
        return False
    if any(not isinstance(item, dict) or len(item) != 1 for item in records):
        return False
    objects = [item for item in records if isinstance(item, dict) and "metainfo" not in item]
    if len(objects) != 4 or any(len(item) != 1 for item in objects):
        return False
    by_type = {next(iter(item)): next(iter(item.values())) for item in objects}
    if set(by_type) != {"table", "set", "chain", "rule"}:
        return False
    root = by_type["table"]
    owned_set = by_type["set"]
    chain = by_type["chain"]
    rule = by_type["rule"]
    if not all(isinstance(item, dict) for item in (root, owned_set, chain, rule)):
        return False
    identity = root.get("comment")
    if (
        not isinstance(identity, str)
        or not IDENTITY.fullmatch(identity)
        or table != f"terminus_{identity[:24]}"
        or root.get("family") != "inet"
        or root.get("name") != table
    ):
        return False
    return (
        owned_set.get("family") == "inet"
        and owned_set.get("table") == table
        and owned_set.get("name") == "blocked"
        and owned_set.get("elem", []) == []
        and chain.get("family") == "inet"
        and chain.get("table") == table
        and chain.get("name") == "incoming"
        and rule.get("family") == "inet"
        and rule.get("table") == table
        and rule.get("chain") == "incoming"
    )


def main() -> int:
    """Run cleanup or handle one stdin message; every failure is reported as unknown.

    For a stdin message the exit status is 0 only for an accepted or already-owned result.
    A failure prints a generic unknown state and logs a truncated reason, so alert data is
    never echoed back.
    """
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--cleanup-expired":
            result = cleanup_expired()
            if result["removed"]:
                log_status(f"expired tables removed: {len(result['removed'])}")
                print(json.dumps(result))
            return 0
        if len(sys.argv) != 1:
            raise ValueError("Unsupported arguments")
        raw = sys.stdin.buffer.readline(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT or not raw.endswith(b"\n"):
            raise ValueError("Invalid message size")
        result = execute(json.loads(raw))
        log_status(result["state"])
        # Wazuh captures command output; this is not independent verification.
        print(json.dumps(result))
        return 0 if result["state"] in {"accepted", "already_owned"} else 1
    except (
        ValueError,
        KeyError,
        TypeError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        log_status(f"unknown ({type(exc).__name__}: {str(exc)[:100]})")
        print('{"state":"unknown","verified":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
