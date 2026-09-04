from __future__ import annotations

from terminus.core.ids import OrgId
from terminus.models import PolicyResult, SiemAlert, Tier


class PolicyEngine:
    def evaluate(self, alert: SiemAlert, org_id: OrgId) -> PolicyResult:
        level = alert.level
        if level >= 10 or (alert.mitre and alert.mitre.startswith("T")):
            tier = Tier.ESCALATE
            should_investigate = True
            reason = "High alert level or critical MITRE technique"
        elif level >= 5:
            tier = Tier.TRIAGE
            should_investigate = True
            reason = "Medium alert level requires triage"
        else:
            tier = Tier.IGNORE
            should_investigate = False
            reason = "Low alert level, ignored"

        return PolicyResult(
            alert_id=alert.id,
            tier=tier,
            should_investigate=should_investigate,
            reason=reason,
        )
