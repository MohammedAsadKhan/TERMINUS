from __future__ import annotations

from typing import Protocol

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport


class Notifier(Protocol):
    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool: ...
