from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import Evidence, SiemAlert
from terminus.siem.base import SiemClient


class InvestigationTools:
    def __init__(self, siem: SiemClient) -> None:
        self.siem = siem

    async def gather_evidence(self, alert: SiemAlert, org_id: OrgId) -> Evidence:
        del org_id
        agent_name = alert.agent_name
        context_gaps: list[str] = []
        if alert.agent_id and not agent_name:
            try:
                agent_info = await self.siem.get_agent(alert.agent_id)
                agent_name = agent_info.get("name")
            except Exception as exc:
                context_gaps.append(
                    f"Endpoint context unavailable: {type(exc).__name__}."
                )

        threat_intel = "Not assessed. No external threat intelligence provider was queried."
        if alert.hash:
            threat_intel = (
                "Hash reputation not assessed. No external threat intelligence "
                "provider was queried."
            )

        context_notes = "\n".join(context_gaps)
        if alert.mitre:
            context_notes += f"\nMITRE Technique: {alert.mitre}"

        return Evidence(
            alert=alert,
            agent_name=agent_name,
            threat_intel=threat_intel,
            context_notes=context_notes,
        )
