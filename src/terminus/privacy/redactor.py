"""Local PII, Credential, and Secret Redaction Engine for TERMINUS.

Ensures zero-latency client-side scrubbing of sensitive enterprise credentials,
API tokens, and PII before telemetry reaches external LLM inference endpoints.
"""

from __future__ import annotations

import re
from typing import Any


class SecretRedactor:
    """Regex-based high-speed secret and PII redaction filter."""

    # Patterns for secrets and tokens
    PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # AWS Access Key & Secret Key
        (re.compile(r"\bAKIA[0-9A-Z]{16,28}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
        (re.compile(r"\baws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}\b", re.IGNORECASE), "aws_secret_access_key=[REDACTED_AWS_SECRET]"),
        # Generic Bearer & JWT tokens
        (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT_TOKEN]"),
        (re.compile(r"\bBearer\s+[A-Za-z0-9_\-\.]{20,}\b", re.IGNORECASE), "Bearer [REDACTED_BEARER_TOKEN]"),
        # Basic Auth in URLs / commands
        (re.compile(r"://([^:\s]+):([^@\s]+)@"), r"://\1:[REDACTED_PASSWORD]@"),
        (re.compile(r"-u\s+([^\s:]+):([^\s]+)", re.IGNORECASE), r"-u \1:[REDACTED_PASSWORD]"),
        (re.compile(r"(password|passwd|pwd|secret|api_key|apikey)[\s:=]+['\"]?([^\s'\";,]{6,})['\"]?", re.IGNORECASE), r"\1=[REDACTED_SECRET]"),
        # GitHub Tokens
        (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "[REDACTED_GITHUB_TOKEN]"),
        (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "[REDACTED_GITHUB_PAT]"),
        # Google Cloud API Keys
        (re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"), "[REDACTED_GCP_API_KEY]"),
        # Azure SAS Token Signature
        (re.compile(r"sig=[A-Za-z0-9%]{40,}", re.IGNORECASE), "sig=[REDACTED_AZURE_SAS]"),
        # Credit Card Numbers (Major Brands)
        (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "[REDACTED_CREDIT_CARD]"),
        # US Social Security Numbers
        (re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "[REDACTED_SSN]"),
    ]

    SECRET_KEY_SUBSTRINGS = (
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
    )

    @classmethod
    def redact(cls, text: str) -> str:
        """Redacts all sensitive tokens, credentials, and PII from the provided string."""
        if not text:
            return text

        scrubbed = text
        for pattern, replacement in cls.PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed

    @classmethod
    def redact_dict(cls, data: Any) -> Any:
        """Recursively redacts dictionary and list structures by key name and value pattern."""
        if isinstance(data, dict):
            redacted: dict[str, Any] = {}
            for k, v in data.items():
                k_str = str(k).lower()
                if any(sub in k_str for sub in cls.SECRET_KEY_SUBSTRINGS):
                    redacted[k] = "[REDACTED]"
                else:
                    redacted[k] = cls.redact_dict(v)
            return redacted
        if isinstance(data, list):
            return [cls.redact_dict(item) for item in data]
        if isinstance(data, tuple):
            return tuple(cls.redact_dict(item) for item in data)
        if isinstance(data, str):
            return cls.redact(data)
        return data
