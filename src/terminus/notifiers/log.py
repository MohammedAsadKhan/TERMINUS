# File name: log.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Record notifications locally through the application logger.

from __future__ import annotations

import sys

from terminus.core.ids import OrgId
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class LogNotifier(Notifier):
    """Notifier that prints a one-line report summary to standard output."""
    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        # Model text may contain characters unsupported by a Windows console code page.
        """Print the report summary, escaping characters the console encoding cannot
        show, and return True.
        """
        encoding = sys.stdout.encoding or "utf-8"
        summary = report.verdict.summary.encode(encoding, errors="backslashreplace").decode(encoding)
        print(
            f"[LogNotifier] Org {org_id} | Alert {report.alert_id} | Severity: {report.verdict.severity} | Tier: {report.policy.tier}"
        )
        print(f"Summary: {summary}")
        return True
