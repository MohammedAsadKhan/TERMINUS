from __future__ import annotations

import anyio

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class CompositeNotifier(Notifier):
    def __init__(self, notifiers: list[Notifier]) -> None:
        self.notifiers = notifiers

    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        async with anyio.create_task_group() as tg:
            for notifier in self.notifiers:
                tg.start_soon(notifier.notify, report, org_id)
        return True
