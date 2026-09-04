from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class LogNotifier(Notifier):
    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        print(
            f"[LogNotifier] Org {org_id} | Alert {report.alert_id} | Severity: {report.verdict.severity} | Tier: {report.policy.tier}"
        )
        print(f"Summary: {report.verdict.summary}")
        return True
