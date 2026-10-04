"""Live Threat Intelligence Integration (VirusTotal, AbuseIPDB, GreyNoise) with TTL caching."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

from terminus.http import create_async_client

logger = logging.getLogger("terminus.tools.threat_intel")


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str  # "hash", "ipv4", "domain", "cve"
    is_malicious: bool | None
    reputation_score: float | None  # 0.0 to 1.0 when checked; None when unknown
    threat_names: list[str] = field(default_factory=list)
    confidence: str = "UNKNOWN"
    provider: str = "No external provider queried"
    details: str = ""

    def to_citation(self) -> dict[str, Any]:
        if self.provider == "No external provider queried":
            return {
                "status": "not_assessed",
                "queried": False,
                "indicator": self.indicator,
                "type": self.indicator_type,
                "summary": self.details,
            }
        return {
            "source": f"ThreatIntel:{self.provider}",
            "queried": True,
            "indicator": self.indicator,
            "type": self.indicator_type,
            "malicious": self.is_malicious,
            "score": self.reputation_score,
            "summary": self.details,
        }


class ThreatIntelClient:
    """Multi-source threat intelligence lookup engine with TTL cache."""

    def __init__(
        self,
        vt_api_key: str = "",
        abuseipdb_key: str = "",
        greynoise_key: str = "",
        cache_ttl_sec: float = 86400.0,
    ) -> None:
        self.vt_api_key = vt_api_key
        self.abuseipdb_key = abuseipdb_key
        self.greynoise_key = greynoise_key
        self.cache_ttl_sec = cache_ttl_sec
        self._cache: dict[str, tuple[float, ThreatIntelResult]] = {}

    async def lookup(self, indicator: str, indicator_type: str = "auto") -> ThreatIntelResult:
        """Query threat intelligence for a given indicator (hash, IP, domain, CVE)."""
        indicator = indicator.strip()
        if not indicator:
            return ThreatIntelResult(indicator="", indicator_type="unknown", is_malicious=None, reputation_score=None)

        # Check cache
        cached = self._cache.get(indicator)
        if cached:
            cached_time, result = cached
            if time.time() - cached_time < self.cache_ttl_sec:
                return result

        # Determine indicator type
        if indicator_type == "auto":
            if len(indicator) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in indicator):
                indicator_type = "hash"
            elif indicator.count(".") == 3 and all(p.isdigit() for p in indicator.split(".")):
                indicator_type = "ipv4"
            elif indicator.upper().startswith("CVE-"):
                indicator_type = "cve"
            else:
                indicator_type = "domain"

        # Query live or deterministic intelligence
        result = await self._query_provider(indicator, indicator_type)
        self._cache[indicator] = (time.time(), result)
        return result

    async def _query_provider(self, indicator: str, indicator_type: str) -> ThreatIntelResult:
        # 1. Live VirusTotal Hash Lookup
        if indicator_type == "hash" and self.vt_api_key:
            try:
                async with create_async_client() as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/files/{indicator}",
                        headers={"x-apikey": self.vt_api_key},
                        timeout=5.0,
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        attr = data.get("attributes", {})
                        stats = attr.get("last_analysis_stats", {})
                        mal = stats.get("malicious", 0)
                        tot = mal + stats.get("undetected", 0) + stats.get("harmless", 0)
                        score = mal / max(tot, 1)
                        names = list(attr.get("popular_threat_classification", {}).get("suggested_threat_label", []))
                        return ThreatIntelResult(
                            indicator=indicator,
                            indicator_type="hash",
                            is_malicious=mal > 2,
                            reputation_score=score,
                            threat_names=names,
                            provider="VirusTotal v3",
                            details=f"VirusTotal detected {mal}/{tot} security vendor engines flagging hash as malicious.",
                        )
            except Exception as e:
                logger.warning(f"VirusTotal lookup error for {indicator}: {e}")

        # 2. Live AbuseIPDB IP Lookup
        if indicator_type == "ipv4" and self.abuseipdb_key:
            try:
                async with create_async_client() as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                        params={"ipAddress": indicator, "maxAgeInDays": "90"},
                        timeout=5.0,
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = float(data.get("abuseConfidenceScore", 0)) / 100.0
                        total_reports = data.get("totalReports", 0)
                        return ThreatIntelResult(
                            indicator=indicator,
                            indicator_type="ipv4",
                            is_malicious=score > 0.4,
                            reputation_score=score,
                            threat_names=["Abusive Host"] if score > 0.4 else [],
                            provider="AbuseIPDB",
                            details=f"AbuseIPDB Confidence Score: {int(score * 100)}% across {total_reports} reports.",
                        )
            except Exception as e:
                logger.warning(f"AbuseIPDB lookup error for {indicator}: {e}")

        # Local string matches are context only; they cannot establish reputation.
        if indicator_type == "ipv4":
            # Check private RFC 1918
            parts = indicator.split(".")
            if len(parts) == 4 and (
                parts[0] in ("10", "127")
                or (parts[0] == "172" and 16 <= int(parts[1]) <= 31)
                or (parts[0] == "192" and parts[1] == "168")
            ):
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type="ipv4",
                    is_malicious=None,
                    reputation_score=None,
                    threat_names=[],
                    provider="No external provider queried",
                    details=(
                        "Private network address classification only. No external "
                        "reputation check was performed; malicious reputation is unknown."
                    ),
                )
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ipv4",
                is_malicious=None,
                reputation_score=None,
                threat_names=[],
                provider="No external provider queried",
                details="Public IP address. No external reputation check was performed; malicious reputation is unknown.",
            )

        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            is_malicious=None,
            reputation_score=None,
            threat_names=[],
            provider="No external provider queried",
            details=(
                "No external reputation check was performed; malicious reputation "
                "is unknown. Local string matches, if any, are unverified context only."
            ),
        )
