# File name: builder.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Select notification adapters from the configured delivery settings.

from __future__ import annotations

import anyio

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class CompositeNotifier(Notifier):
    """Fan a report out to several notifiers concurrently."""
    def __init__(self, notifiers: list[Notifier]) -> None:
        """Keep the child notifiers to call."""
        self.notifiers = notifiers

    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        """Run every child notifier in one task group and return True once all finish; a
        child failure propagates out of the group.
        """
        async with anyio.create_task_group() as tg:
            for notifier in self.notifiers:
                tg.start_soon(notifier.notify, report, org_id)
        return True
