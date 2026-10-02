from __future__ import annotations

import sys

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class LogNotifier(Notifier):
    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        # Model text may contain characters unsupported by a Windows console code page.
        encoding = sys.stdout.encoding or "utf-8"
        summary = report.verdict.summary.encode(encoding, errors="backslashreplace").decode(encoding)
        print(
            f"[LogNotifier] Org {org_id} | Alert {report.alert_id} | Severity: {report.verdict.severity} | Tier: {report.policy.tier}"
        )
        print(f"Summary: {summary}")
        return True
