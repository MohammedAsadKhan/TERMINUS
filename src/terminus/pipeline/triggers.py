"""SIEM Alert Trigger Matching Engine for TERMINUS.

Provides single-source-of-truth alert matching logic used both for workflow
matching prior to execution and within trigger_wazuh nodes during workflow runs (D2).
"""

from __future__ import annotations

from typing import Any

from terminus.models import SiemAlert
from terminus.pipeline.nodes.schemas import TriggerWazuhConfig


def trigger_matches(cfg: TriggerWazuhConfig | dict[str, Any], alert: SiemAlert) -> bool:
    """Evaluates whether an incoming SiemAlert matches a trigger_wazuh configuration."""
    if isinstance(cfg, dict):
        try:
            config = TriggerWazuhConfig.model_validate(cfg)
        except Exception:
            return False
    else:
        config = cfg

    # 1. min_level check
    if alert.level < config.min_level:
        return False

    # 2. single rule_id check
    if config.rule_id is not None:
        try:
            if int(alert.rule_id) != int(config.rule_id):
                return False
        except (ValueError, TypeError):
            if str(alert.rule_id) != str(config.rule_id):
                return False

    # 3. multiple rule_ids check
    if config.rule_ids:
        matched = False
        for rid in config.rule_ids:
            try:
                if int(alert.rule_id) == int(rid):
                    matched = True
                    break
            except (ValueError, TypeError):
                if str(alert.rule_id) == str(rid):
                    matched = True
                    break
        if not matched:
            return False

    # 4. location match
    if config.location:
        if config.location.lower() not in (alert.location or "").lower():
            return False

    # 5. mitre match
    if config.mitre:
        if not alert.mitre or config.mitre.lower() not in alert.mitre.lower():
            return False

    # 6. agent_name match
    if config.agent_name_match:
        if not alert.agent_name or config.agent_name_match.lower() not in alert.agent_name.lower():
            return False

    return True
