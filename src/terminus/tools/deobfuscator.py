"""Static Script and Payload De-obfuscation Engine for TERMINUS 2.0.

Automatically decodes Base64 payloads, PowerShell encoded commands,
hex-encoded strings, and URL-encoded command strings.
"""

from __future__ import annotations

import base64
import re
import urllib.parse
from dataclasses import dataclass, field


@dataclass
class DeobfuscationResult:
    original: str
    deobfuscated: str
    encoding_type: str
    suspicious_patterns_found: list[str] = field(default_factory=list)


class PayloadDeobfuscator:
    """De-obfuscates obfuscated adversary command lines and payloads."""

    POWERSHELL_ENC_REGEX = re.compile(
        r"(?:-enc|-encodedcommand|-e)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE
    )
    BASE64_GENERIC_REGEX = re.compile(r"\b([A-Za-z0-9+/]{24,}={0,2})\b")

    DANGEROUS_COMMANDS = [
        "iex", "invoke-expression", "downloadstring", "bitstransfer",
        "mimikatz", "sekurlsa", "lsass", "rundll32", "regsvr32",
        "certutil", "vssadmin", "wbadmin", "bcdedit", "wmic", "powershell",
        "/bin/sh", "/bin/bash", "curl", "wget", "chmod +x", "nc -e",
    ]

    @classmethod
    def deobfuscate(cls, text: str) -> DeobfuscationResult | None:
        """Attempts to de-obfuscate the command text if encoded."""
        if not text:
            return None

        # 1. PowerShell UTF-16LE Base64 Encoded Commands
        ps_match = cls.POWERSHELL_ENC_REGEX.search(text)
        if ps_match:
            b64_str = ps_match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_text = decoded_bytes.decode("utf-16le", errors="ignore")
                if len(decoded_text.strip()) > 3:
                    findings = [cmd for cmd in cls.DANGEROUS_COMMANDS if cmd in decoded_text.lower()]
                    return DeobfuscationResult(
                        original=text,
                        deobfuscated=decoded_text.strip(),
                        encoding_type="PowerShell UTF-16LE Base64",
                        suspicious_patterns_found=findings,
                    )
            except Exception:
                pass

        # 2. URL-encoded payloads
        if "%20" in text or "%2F" in text.upper() or "%3C" in text.upper():
            try:
                decoded = urllib.parse.unquote(text)
                if decoded != text:
                    findings = [cmd for cmd in cls.DANGEROUS_COMMANDS if cmd in decoded.lower()]
                    return DeobfuscationResult(
                        original=text,
                        deobfuscated=decoded,
                        encoding_type="URL Encoding",
                        suspicious_patterns_found=findings,
                    )
            except Exception:
                pass

        # 3. Standard ASCII Base64 blobs
        b64_match = cls.BASE64_GENERIC_REGEX.search(text)
        if b64_match:
            b64_str = b64_match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_str)
                decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                if len(decoded_text.strip()) > 5 and any(c.isalnum() for c in decoded_text):
                    findings = [cmd for cmd in cls.DANGEROUS_COMMANDS if cmd in decoded_text.lower()]
                    return DeobfuscationResult(
                        original=text,
                        deobfuscated=decoded_text.strip(),
                        encoding_type="Standard Base64 UTF-8",
                        suspicious_patterns_found=findings,
                    )
            except Exception:
                pass

        return None
