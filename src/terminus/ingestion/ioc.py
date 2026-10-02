"""High-speed IOC (Indicators of Compromise) extraction and pattern matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ExtractedIocs:
    ipv4s: list[str] = field(default_factory=list)
    ipv6s: list[str] = field(default_factory=list)
    sha256s: list[str] = field(default_factory=list)
    md5s: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)


class IocExtractor:
    """Extracts network, cryptographic, and vulnerability indicators from raw text."""

    IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
    MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
    CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    MITRE_REGEX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
    DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
    URL_REGEX = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

    # Common internal/benign domains to ignore
    IGNORED_DOMAINS = {"w3.org", "apache.org", "github.com", "microsoft.com", "google.com", "schema.org"}

    @classmethod
    def extract(cls, text: str) -> ExtractedIocs:
        if not text:
            return ExtractedIocs()

        ipv4s = list(set(cls.IPV4_REGEX.findall(text)))
        sha256s = list(set(cls.SHA256_REGEX.findall(text)))
        md5s = list(set(cls.MD5_REGEX.findall(text)))
        cves = [c.upper() for c in set(cls.CVE_REGEX.findall(text))]
        mitre_techs = [m.upper() for m in set(cls.MITRE_REGEX.findall(text))]
        urls = list(set(cls.URL_REGEX.findall(text)))

        domains_raw = set(cls.DOMAIN_REGEX.findall(text))
        domains = [d.lower() for d in domains_raw if d.lower() not in cls.IGNORED_DOMAINS and not cls.IPV4_REGEX.match(d)]

        return ExtractedIocs(
            ipv4s=ipv4s,
            sha256s=sha256s,
            md5s=md5s,
            domains=domains,
            urls=urls,
            cves=cves,
            mitre_techniques=mitre_techs,
        )
