from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import Evidence, SiemAlert
from terminus.siem.base import SiemClient


class InvestigationTools:
    def __init__(self, siem: SiemClient) -> None:
        self.siem = siem

    async def gather_evidence(self, alert: SiemAlert, org_id: OrgId) -> Evidence:
        agent_name = alert.agent_name
        if alert.agent_id and not agent_name:
            try:
                agent_info = await self.siem.get_agent(alert.agent_id)
                agent_name = agent_info.get("name")
            except Exception:
                pass

        threat_intel = "Clean"
        if alert.hash:
            # Mock VirusTotal lookup
            threat_intel = f"Hash {alert.hash} found in threat intel."

        context_notes = ""
        if alert.mitre:
            context_notes += f"MITRE Technique: {alert.mitre}\n"

        return Evidence(
            alert=alert,
            agent_name=agent_name,
            threat_intel=threat_intel,
            context_notes=context_notes,
        )
