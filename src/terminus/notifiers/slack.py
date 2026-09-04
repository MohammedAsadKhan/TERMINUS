"""Slack incoming webhook notifier implementation."""

from __future__ import annotations

import httpx2

from terminus.core.ids import OrgId
from terminus.http import create_async_client
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class SlackNotifier(Notifier):
    """Notifier for Slack incoming webhooks."""

    _webhook_url: str
    _client: httpx2.AsyncClient

    def __init__(
        self,
        webhook_url: str = "",
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Initialize Slack notifier."""
        self._webhook_url = webhook_url
        self._client = client or create_async_client()

    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        """Send investigation verdict notification to Slack channel."""
        if not self._webhook_url:
            return False

        alert = report.evidence.alert
        payload = {
            "text": f"🚨 *Terminus Investigation Report* [Org: `{org_id}`]\n"
            f"*Alert ID:* `{alert.id}` (Level {alert.level})\n"
            f"*Verdict:* *{report.verdict.severity.value.upper()}* "
            f"(Confidence: {report.verdict.confidence.value})\n"
            f"*Summary:* {report.verdict.summary}\n"
            f"*Recommended Actions:* {', '.join(report.verdict.recommended_actions)}",
        }

        try:
            res = await self._client.post(self._webhook_url, json=payload)
            return res.is_success
        except Exception:
            return False
