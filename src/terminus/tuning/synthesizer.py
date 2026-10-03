"""Dynamic Sigma & YARA Detection Rule Synthesizer for TERMINUS.

Synthesizes validated detection rules from triaged incident artifacts,
MITRE ATT&CK techniques, and extracted IOCs.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from terminus.ingestion.ioc import IocExtractor
from terminus.models import InvestigationReport, SiemAlert
from terminus.tools.deobfuscator import PayloadDeobfuscator


class RuleStatus(StrEnum):
    EXPERIMENTAL = "experimental"
    TEST = "test"
    STABLE = "stable"


class RuleSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SigmaRule:
    title: str
    description: str
    detection: dict[str, Any]
    level: RuleSeverity = RuleSeverity.HIGH
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    author: str = "TERMINUS Autonomous Detection Synthesizer"
    date: str = field(default_factory=lambda: datetime.now(UTC).strftime("%Y/%m/%d"))
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=lambda: ["Legitimate administrative scripts", "Verified software deployments"])

    def to_yaml(self) -> str:
        """Serialize into compliant Sigma YAML format."""
        lines = [
            f"title: {self.title}",
            f"id: {self.id}",
            f"status: {self.status.value}",
            f"description: {self.description}",
            f"author: {self.author}",
            f"date: {self.date}",
            f"level: {self.level.value}",
        ]
        if self.tags:
            lines.append("tags:")
            for tag in self.tags:
                lines.append(f"  - {tag}")
        lines.append("logsource:")
        lines.append("  category: process_creation")
        lines.append("  product: windows")
        lines.append("detection:")
        lines.append("  selection:")
        for k, v in self.detection.get("selection", {}).items():
            if isinstance(v, list):
                lines.append(f"    {k}:")
                for item in v:
                    lines.append(f"      - '{item}'")
            else:
                lines.append(f"    {k}: '{v}'")
        lines.append(f"  condition: {self.detection.get('condition', 'selection')}")
        lines.append("falsepositives:")
        for fp in self.falsepositives:
            lines.append(f"  - '{fp}'")
        return "\n".join(lines)


@dataclass
class YaraRule:
    rule_name: str
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[tuple[str, str]] = field(default_factory=list)
    condition: str = "filesize < 10MB and any of ($*)"

    def to_yara_source(self) -> str:
        """Serialize into valid YARA rule syntax."""
        meta_lines = "\n".join([f'        {k} = "{v}"' for k, v in self.meta.items()])
        str_lines = "\n".join([f'        {ident} = "{val}" ascii wide nocase' for ident, val in self.strings])
        return f"""rule {self.rule_name}
{{
    meta:
{meta_lines}
    strings:
{str_lines}
    condition:
        {self.condition}
}}"""


class RuleSynthesizer:
    """Dynamically synthesizes Sigma and YARA detection rules from incident telemetry."""

    @classmethod
    def synthesize_sigma_rule(
        cls,
        alert: SiemAlert,
        report: InvestigationReport | None = None,
    ) -> SigmaRule:
        """Generate a structured Sigma rule from alert and investigation context."""
        tags = []
        if alert.mitre:
            mitre_clean = alert.mitre.lower().replace(".", "_").replace(" ", "")
            tags.append(f"attack.{mitre_clean}")

        selection: dict[str, Any] = {}
        if alert.agent_name:
            selection["Image|endswith"] = [alert.agent_name]

        deobf = PayloadDeobfuscator.deobfuscate(alert.full_log or "")
        cmd_tokens: list[str] = []
        if deobf and deobf.suspicious_patterns_found:
            cmd_tokens.extend(deobf.suspicious_patterns_found)
        elif "-enc" in (alert.full_log or "").lower():
            cmd_tokens.extend(["-enc", "-EncodedCommand"])

        if cmd_tokens:
            selection["CommandLine|contains"] = list(set(cmd_tokens))
        elif alert.description:
            selection["CommandLine|contains"] = [alert.description[:35]]

        severity_level = RuleSeverity.HIGH
        if report and report.verdict:
            try:
                severity_level = RuleSeverity(report.verdict.severity.value.lower())
            except Exception:
                severity_level = RuleSeverity.HIGH

        desc = alert.rule_description or alert.description
        summary = report.verdict.summary if (report and report.verdict) else "Automated incident investigation"

        return SigmaRule(
            title=f"Autonomous Rule: {desc}",
            description=f"Auto-generated detection rule for {desc}. Context: {summary[:120]}",
            tags=tags,
            detection={"selection": selection, "condition": "selection"},
            level=severity_level,
        )

    @classmethod
    def synthesize_yara_rule(
        cls,
        alert: SiemAlert,
        report: InvestigationReport | None = None,
    ) -> YaraRule:
        """Generate a structured YARA payload rule from alert indicators."""
        clean_id = alert.id.replace("-", "_").replace(".", "_")[:12]
        rule_name = f"TERMINUS_AUTORULE_{clean_id}"
        meta = {
            "description": f"Incident payload detector for {alert.description}",
            "alert_id": alert.id,
            "created": datetime.now(UTC).isoformat(),
            "author": "TERMINUS Synthesizer",
        }
        strings: list[tuple[str, str]] = []
        iocs = IocExtractor.extract(alert.full_log or alert.description)
        idx = 1
        for sha in iocs.sha256s[:2]:
            strings.append((f"$sha_{idx}", sha))
            idx += 1
        for ip in iocs.ipv4s[:2]:
            strings.append((f"$ip_{idx}", ip))
            idx += 1
        if not strings:
            strings.append(("$s1", "powershell.exe"))

        return YaraRule(
            rule_name=rule_name,
            meta=meta,
            strings=strings,
            condition="filesize < 10MB and any of ($*)",
        )
