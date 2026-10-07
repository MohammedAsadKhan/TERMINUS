#!/usr/bin/python3
"""Wazuh endpoint command for the isolated Scenario A lab only.

Install root-owned on terminus-target-a. No model arguments, shell, arbitrary
targets or credentials. nftables expires the blocked set element independently
of the Windows worker. Empty tables remain until an ownership-checked delete.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from collections.abc import Callable
from typing import Any

NFT = "/usr/sbin/nft"
SOURCE = "10.77.0.10"
MAX_INPUT = 8192


def plan(message: dict) -> tuple[str, str, str, int]:
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
    return (
        f'add table inet {table} {{ comment "{identity}"; }}\n'
        f"add set inet {table} blocked {{ type ipv4_addr; flags timeout; }}\n"
        f"add element inet {table} blocked {{ {SOURCE} timeout {duration}s }}\n"
        f"add chain inet {table} incoming {{ type filter hook input priority -10; policy accept; }}\n"
        f"add rule inet {table} incoming ip saddr @blocked drop\n"
    )


def execute(message: dict, runner: Callable[..., Any] = subprocess.run) -> dict:
    command, table, identity, duration = plan(message)
    observed = runner(
        [NFT, "--json", "list", "table", "inet", table],
        capture_output=True,
        timeout=5,
        check=False,
    )
    if observed.returncode == 0:
        if len(observed.stdout) > 65536:
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


def main() -> int:
    try:
        raw = sys.stdin.buffer.readline(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT or not raw.endswith(b"\n"):
            raise ValueError("Invalid message size")
        result = execute(json.loads(raw))
        # Wazuh captures command output; this is not independent verification.
        print(json.dumps(result))
        return 0 if result["state"] in {"accepted", "already_owned"} else 1
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        print('{"state":"unknown","verified":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
