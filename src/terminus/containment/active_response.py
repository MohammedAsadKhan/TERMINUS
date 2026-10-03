"""Guardrailed dispatch boundary for active containment actions.

No live host, firewall, or IAM providers are currently configured. Eligible
actions therefore return an explicit not-configured result; they never report
execution or verification that did not happen.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from terminus.containment.guardrails import ContainmentGuardrail
from terminus.siem.base import SiemClient

logger = logging.getLogger("terminus.containment.active_response")


@dataclass
class ContainmentResult:
    success: bool
    action_type: str
    target: str
    operator_id: str
    audit_message: str
    raw_response: dict[str, Any]


class ActiveResponseRunner:
    """Checks containment guardrails and reports whether an action can run."""

    def __init__(self, siem_client: SiemClient | None = None) -> None:
        self.siem = siem_client

    async def execute_containment(
        self,
        action_type: str,
        target: str,
        operator_id: str,
        force_override: bool = False,
        org_id: str = "org-default",
        allowlist_repo: Any | None = None,
    ) -> ContainmentResult:
        """Executes a containment action with blast radius checks."""
        # 1. Check Blast Radius (D11 & D12)
        kind = "ip" if action_type == "block_ip" else "host"
        assessment = ContainmentGuardrail.assess_target(
            target=target,
            kind=kind,
            org_id=org_id,
            allowlist_repo=allowlist_repo,
            force_override=force_override,
        )
        if not assessment.allowed:
            return ContainmentResult(
                success=False,
                action_type=action_type,
                target=target,
                operator_id=operator_id,
                audit_message=f"CONTAINMENT BLOCKED: {assessment.rationale}",
                raw_response={"blocked": True, "assessment": assessment.__dict__},
            )

        # 2. Dispatch Action
        if action_type == "isolate_host":
            return ContainmentResult(
                success=False,
                action_type=action_type,
                target=target,
                operator_id=operator_id,
                audit_message=f"CONTAINMENT NOT EXECUTED: no host isolation provider is configured for '{target}'.",
                raw_response={"status": "not_configured", "executed": False, "verified": False},
            )

        if action_type == "block_ip":
            return ContainmentResult(
                success=False,
                action_type=action_type,
                target=target,
                operator_id=operator_id,
                audit_message=f"CONTAINMENT NOT EXECUTED: no firewall provider is configured for '{target}'.",
                raw_response={"status": "not_configured", "executed": False, "verified": False},
            )

        if action_type == "revoke_iam_session":
            return ContainmentResult(
                success=False,
                action_type=action_type,
                target=target,
                operator_id=operator_id,
                audit_message=f"CONTAINMENT NOT EXECUTED: no IAM session revocation provider is configured for '{target}'.",
                raw_response={"status": "not_configured", "executed": False, "verified": False},
            )

        return ContainmentResult(
            success=False,
            action_type=action_type,
            target=target,
            operator_id=operator_id,
            audit_message=f"Unknown containment action '{action_type}'",
            raw_response={},
        )
