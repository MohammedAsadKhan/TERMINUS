# File name: base.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Define the interface for sending investigation notifications.

from __future__ import annotations

from typing import Protocol

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport


class Notifier(Protocol):
    """Contract for sending an investigation report to an external channel on behalf of
    one organization.
    """
    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool: ...
