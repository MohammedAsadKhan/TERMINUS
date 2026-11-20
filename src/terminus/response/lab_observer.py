# File name: lab_observer.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Fixed read-only SSH observations for the isolated autonomous lab controller.

"""Fixed read-only SSH observations for the isolated autonomous lab controller."""

from __future__ import annotations

import asyncio
import hashlib
import json
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any


class LabSSHObserver:
    """Uses existing SSH keys and known_hosts. No passwords or host-key bypass."""

    def __init__(
        self, kali_management_ip: str, target_management_ip: str = "192.168.56.103"
    ) -> None:
        """Accept only addresses on the lab management network (excluding network,
        gateway and broadcast hosts), so the observer can never be pointed at a non- lab
        machine.
        """
        for address in (kali_management_ip, target_management_ip):
            parsed = IPv4Address(address)
            if str(parsed).rsplit(".", 1)[0] != "192.168.56" or parsed.packed[-1] in {
                0,
                1,
                255,
            }:
                raise ValueError("Observer SSH endpoints must be lab management guests")
        self.kali, self.target = kali_management_ip, target_management_ip

    async def _read(self, user: str, host: str, command: str) -> tuple[int, str]:
        """Run one read-only command over SSH with key-only auth, strict host-key
        checking and a 6 second cap, returning (1, '') on timeout, oversized output or
        missing output so callers fail closed.
        """
        process = await asyncio.create_subprocess_exec(
            "ssh",
            "-i",
            str(Path.home() / ".ssh" / "terminus_lab_ed25519"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=3",
            f"{user}@{host}",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=65536,
        )
        try:
            async with asyncio.timeout(6):
                if process.stdout is None:
                    return 1, ""
                output = await process.stdout.read(65537)
                if len(output) > 65536:
                    return 1, ""
                status = await process.wait()
                return status, output.decode(errors="replace")
        except TimeoutError:
            return 1, ""
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    async def __call__(self, stage: str, details: dict[str, Any]) -> bool:  # noqa: C901, PLR0911 -- independent verification gates
        """Independently verify one lifecycle stage (baseline, table-absent, blocked or
        recovered) from the target's nftables state and a probe from the source host.
        Returns True only when every check passes; any error or ambiguity returns False.
        """
        # Order of gates: first confirm the management path reaches the expected target
        # (so results are not read from the wrong machine), then probe from the source
        # host, and only then inspect firewall state for the requested stage.
        management, name = await self._read("labadmin", self.target, "hostname")
        if management != 0 or name.strip() != "terminus-target-a":
            return False
        source, result = await self._read(
            "kali", self.kali, "nc -z -w 2 10.77.0.20 22; printf 'PROBE_STATUS:%s' $?"
        )
        if source != 0 or result.strip() not in {"PROBE_STATUS:0", "PROBE_STATUS:1"}:
            return False
        reachable = result.strip() == "PROBE_STATUS:0"
        if stage == "baseline":
            status, _ = await self._read(
                "labadmin", self.target, "sudo -n /usr/sbin/nft --json list tables"
            )
            return reachable and status == 0
        # The table name and comment are derived from the intent and approved digest, so
        # only a table created for exactly this approved action counts as owned.
        identity = hashlib.sha256(
            f"{details['intent_id']}:{details['proposal_digest']}".encode()
        ).hexdigest()
        table = "terminus_" + identity[:24]
        if stage == "table-absent":
            status, output = await self._read(
                "labadmin", self.target, "sudo -n /usr/sbin/nft --json list tables"
            )
            if status != 0 or not reachable:
                return False
            try:
                tables = json.loads(output)["nftables"]
                return not any(
                    item.get("table", {}).get("family") == "inet"
                    and item.get("table", {}).get("name") == table
                    for item in tables
                )
            except (ValueError, KeyError, TypeError, AttributeError):
                return False
        status, output = await self._read(
            "labadmin",
            self.target,
            f"sudo -n /usr/sbin/nft --json list table inet {table}",
        )
        if status != 0:
            return False
        try:
            nft = json.loads(output)["nftables"]
            owned = any(
                entry.get("table", {}).get("comment") == identity
                and entry.get("table", {}).get("name") == table
                and entry.get("table", {}).get("family") == "inet"
                for entry in nft
            )
            sets = [
                entry["set"]
                for entry in nft
                if "set" in entry
                and entry["set"].get("name") == "blocked"
                and entry["set"].get("table") == table
            ]
            if not owned or len(sets) != 1:
                return False
            elements = sets[0].get("elem", [])
            present = any(
                element == "10.77.0.10"
                or (
                    isinstance(element, dict)
                    and element.get("elem", {}).get("val") == "10.77.0.10"
                )
                for element in elements
            )
            # "blocked" needs the address in the set and the probe denied; "recovered"
            # needs an empty set and the probe reachable again.
            if stage == "blocked":
                return present and not reachable
            return stage == "recovered" and not elements and reachable
        except (ValueError, KeyError, TypeError, AttributeError):
            return False
