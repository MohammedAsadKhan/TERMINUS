from __future__ import annotations

from dataclasses import dataclass

from terminus.agent.investigator import InvestigationAgent
from terminus.notifiers.base import Notifier
from terminus.policies.engine import PolicyEngine
from terminus.ticketing.base import TicketStore


@dataclass(frozen=True)
class PipelineDeployment:
    policy_engine: PolicyEngine
    agent: InvestigationAgent
    notifier: Notifier
    ticket_store: TicketStore
