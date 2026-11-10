# File name: ids.py
# Author: Team LARP
# Date: 2026-11-09
# Version: 0.1.0
# Purpose: Branded ID types shared across the platform.

"""Branded ID types shared across the platform.

Each domain concept gets its own branded primitive so the type system refuses to let a
raw string be passed where an organization ID is expected.
"""

from __future__ import annotations

from typing import NewType

OrgId = NewType("OrgId", str)
UserId = NewType("UserId", str)
TicketId = NewType("TicketId", str)
AgentId = NewType("AgentId", str)
RuleId = NewType("RuleId", int)
SessionToken = NewType("SessionToken", str)
LicenseId = NewType("LicenseId", str)
