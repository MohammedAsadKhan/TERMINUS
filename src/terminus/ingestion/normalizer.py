"""OCSF (Open Cybersecurity Schema Framework) & ECS Schema Normalizer for TERMINUS 2.0.

Normalizes alerts from Wazuh, Sysmon, CrowdStrike, GuardDuty, or generic telemetry
into a canonical domain representation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from terminus.core.ids import AgentId, RuleId
from terminus.ingestion.ioc import ExtractedIocs, IocExtractor
from terminus.models import SiemAlert


class OcsfEvent(BaseModel):
    """Canonical normalized event model adhering to OCSF specifications."""

    event_id: str
    class_uid: int = 1001  # Security Finding / Threat Detection
    category_uid: int = 2  # Findings
    severity_id: int  # 1: Informational, 2: Low, 3: Medium, 4: High, 5: Critical
    activity_name: str
    message: str
    timestamp: str
    src_endpoint_ip: str | None = None
    dst_endpoint_ip: str | None = None
    hostname: str | None = None
    agent_id: str | None = None
    user_name: str | None = None
    file_hash: str | None = None
    cve_id: str | None = None
    mitre_technique: str | None = None
    raw_log: str = ""
    iocs: ExtractedIocs = Field(default_factory=ExtractedIocs)


class SchemaNormalizer:
    """Converts diverse SIEM and telemetry payloads into standardized SiemAlert and OcsfEvent objects."""

    @classmethod
    def normalize_to_alert(cls, payload: dict[str, Any]) -> SiemAlert:
        """Converts arbitrary input JSON into a validated SiemAlert object."""
        # Case 1: Standard Wazuh or Pre-formed SiemAlert
        if "rule" in payload or "rule_id" in payload:
            try:
                alert = SiemAlert.model_validate(payload)
                if alert.full_log:
                    # Enrich IOCs
                    iocs = IocExtractor.extract(f"{alert.description} {alert.full_log} {alert.location}")
                    if not alert.hash and iocs.sha256s:
                        alert = alert.model_copy(update={"hash": iocs.sha256s[0]})
                    if not alert.src_ip and iocs.ipv4s:
                        alert = alert.model_copy(update={"src_ip": iocs.ipv4s[0]})
                    if not alert.mitre and iocs.mitre_techniques:
                        alert = alert.model_copy(update={"mitre": iocs.mitre_techniques[0]})
                return alert
            except Exception:
                pass

        # Case 2: Generic Webhook / Sysmon / CloudTrail Event
        alert_id = str(payload.get("id") or payload.get("event_id") or f"alert-{uuid4().hex[:8]}")
        desc = str(payload.get("description") or payload.get("message") or payload.get("title") or "Generic Security Finding")
        level = int(payload.get("level") or payload.get("severity") or 5)
        rule_id_raw = payload.get("rule_id") or payload.get("ruleId") or 100001
        agent_id_raw = payload.get("agent_id") or payload.get("host") or payload.get("instance_id") or "srv-generic01"
        full_log = str(payload.get("full_log") or payload.get("raw") or desc)

        iocs = IocExtractor.extract(f"{desc} {full_log}")
        hash_val = payload.get("hash") or (iocs.sha256s[0] if iocs.sha256s else None)
        src_ip = payload.get("src_ip") or payload.get("source_ip") or (iocs.ipv4s[0] if iocs.ipv4s else None)
        mitre = payload.get("mitre") or (iocs.mitre_techniques[0] if iocs.mitre_techniques else None)

        return SiemAlert(
            id=alert_id,
            rule_id=RuleId(str(rule_id_raw)),
            level=level,
            description=desc,
            mitre=mitre,
            agent_id=AgentId(str(agent_id_raw)),
            agent_name=str(payload.get("agent_name") or agent_id_raw),
            timestamp=str(payload.get("timestamp") or datetime.now(UTC).isoformat()),
            location=str(payload.get("location") or "network-boundary"),
            hash=hash_val,
            src_ip=src_ip,
            full_log=full_log,
        )

    @classmethod
    def to_ocsf(cls, alert: SiemAlert) -> OcsfEvent:
        """Translates a SiemAlert to an OCSF Canonical Security Finding."""
        iocs = IocExtractor.extract(f"{alert.description} {alert.full_log or ''}")
        sev_map = {1: 1, 2: 1, 3: 2, 4: 2, 5: 3, 6: 3, 7: 3, 8: 4, 9: 4, 10: 5, 11: 5, 12: 5}
        severity_id = sev_map.get(min(max(alert.level, 1), 12), 3)

        return OcsfEvent(
            event_id=alert.id,
            severity_id=severity_id,
            activity_name=alert.description or "Security Detection",
            message=alert.description or "",
            timestamp=alert.timestamp or datetime.now(UTC).isoformat(),
            src_endpoint_ip=alert.src_ip,
            agent_id=str(alert.agent_id) if alert.agent_id else None,
            hostname=alert.agent_name,
            file_hash=alert.hash,
            mitre_technique=alert.mitre,
            raw_log=alert.full_log or "",
            iocs=iocs,
        )
