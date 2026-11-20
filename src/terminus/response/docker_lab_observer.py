# File name: docker_lab_observer.py
# Author: Team LARP
# Revision date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Invoke the fixed independent Docker observer for the disposable SSH lab.

"""Disposable-lab adapter for the separate read-only observer container."""

from __future__ import annotations

import asyncio
import json
import re
import sys
from collections.abc import Mapping
from typing import cast


class DockerLabObserver:
    """Ask the fixed observer container for bounded evidence, never dispatch effects."""

    def __init__(self, *, local_script: bool = False) -> None:
        """Choose whether to run the observer script locally or inside the fixed
        observer container.
        """
        self.local_script: bool = local_script

    async def __call__(self, stage: str, details: Mapping[str, object]) -> bool:  # noqa: PLR0911 -- fail-closed observer gates
        """Ask the observer for one stage's verdict and return True only if it exits
        cleanly with verified true; unknown stages, malformed identifiers, oversized
        output, timeouts and errors all return False.
        """
        if stage not in {"baseline", "blocked", "recovered", "table-absent"}:
            return False
        command = (
            [sys.executable, "/opt/lab/observe.py"]
            if self.local_script
            else [
                "docker",
                "exec",
                "response-observer",
                "python3",
                "/opt/lab/observe.py",
            ]
        )
        command.extend(["--stage", stage])
        # Intent and digest are passed to a subprocess, so they are checked against a
        # strict format first; anything else is treated as untrusted and rejected.
        if stage != "baseline":
            intent = details.get("intent_id")
            digest = details.get("proposal_digest")
            if not isinstance(intent, str) or not re.fullmatch(
                r"[a-f0-9-]{36}", intent
            ):
                return False
            if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
                return False
            command.extend(["--intent", intent, "--digest", digest])
        process: asyncio.subprocess.Process | None = None
        try:
            async with asyncio.timeout(15):
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                if process.stdout is None:
                    return False
                output = await process.stdout.read(65537)
                if len(output) > 65536:
                    _ = process.kill()
                    _ = await process.wait()
                    return False
                if await process.wait() != 0:
                    return False
            raw = cast(object, json.loads(output))
            return (
                isinstance(raw, dict)
                and cast(dict[str, object], raw).get("verified") is True
            )
        except (OSError, TimeoutError, ValueError, TypeError):
            return False
        finally:
            if process is not None and process.returncode is None:
                _ = process.kill()
                _ = await process.wait()
