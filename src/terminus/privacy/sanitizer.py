"""Adversarial Prompt Injection Defense & Data Isolation for TERMINUS 2.0.

Provides strict XML-delimited encapsulation and pre-screening to prevent
threat actors from embedding malicious instructions within security logs.
"""

from __future__ import annotations

import re


class PromptInjectionSanitizer:
    """Detects and isolates potential prompt injection attacks in untrusted security telemetry."""

    INJECTION_INDICATORS = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
        re.compile(r"system\s*override", re.IGNORECASE),
        re.compile(r"do\s+not\s+analyze\s+this", re.IGNORECASE),
        re.compile(r"classify\s+this\s+(?:alert\s+)?as\s+(?:low|benign)", re.IGNORECASE),
        re.compile(r"severity\s*=\s*['\"]?low['\"]?", re.IGNORECASE),
    ]

    @classmethod
    def check_for_injection(cls, raw_text: str) -> bool:
        """Returns True if the raw telemetry contains prompt injection attempts."""
        if not raw_text:
            return False
        return any(pattern.search(raw_text) for pattern in cls.INJECTION_INDICATORS)

    @classmethod
    def sanitize_and_strip(cls, raw_text: str) -> str:
        """Strips identified prompt injection sentences from telemetry payload."""
        if not raw_text:
            return ""
        cleaned = raw_text
        for pattern in cls.INJECTION_INDICATORS:
            cleaned = pattern.sub("[REDACTED_ADVERSARIAL_INSTRUCTION]", cleaned)
        return cleaned

    @classmethod
    def wrap_untrusted_data(cls, tag_name: str, content: str) -> str:
        """Encapsulates untrusted log data in strict XML boundaries with sanitization."""
        stripped = cls.sanitize_and_strip(content)
        sanitized = (
            stripped.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        return f"<{tag_name}>\n{sanitized}\n</{tag_name}>"
