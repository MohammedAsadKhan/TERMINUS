"""Twilio SMS notifier implementation."""

from __future__ import annotations

import httpx2

from terminus.core.ids import OrgId
from terminus.http import create_async_client
from terminus.models import InvestigationReport
from terminus.notifiers.base import Notifier


class TwilioSmsNotifier(Notifier):
    """Notifier for SMS via Twilio API."""

    _account_sid: str
    _auth_token: str
    _from_number: str
    _to_number: str
    _client: httpx2.AsyncClient

    def __init__(
        self,
        account_sid: str = "",
        auth_token: str = "",
        from_number: str = "",
        to_number: str = "",
        client: httpx2.AsyncClient | None = None,
    ) -> None:
        """Initialize Twilio SMS notifier."""
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_number = from_number
        self._to_number = to_number
        self._client = client or create_async_client()

    async def notify(self, report: InvestigationReport, org_id: OrgId) -> bool:
        """Send investigation verdict SMS via Twilio."""
        if not (
            self._account_sid
            and self._auth_token
            and self._from_number
            and self._to_number
        ):
            return False

        url = f"https://api.twilio.com/2010-04-01/Accounts/{self._account_sid}/Messages.json"
        auth = (self._account_sid, self._auth_token)
        alert = report.evidence.alert
        body = (
            f"Terminus [{org_id}] Alert {alert.id}: "
            f"Verdict {report.verdict.severity.value.upper()} - {report.verdict.summary}"
        )
        data = {
            "From": self._from_number,
            "To": self._to_number,
            "Body": body,
        }

        try:
            res = await self._client.post(url, auth=auth, data=data)
            return res.is_success
        except Exception:
            return False
