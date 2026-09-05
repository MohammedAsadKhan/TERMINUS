"""Application settings loaded from environment variables.

All fields have defaults so the app boots offline with zero env vars. Secrets that are
empty at first load are auto-generated in-memory with a logged warning.
"""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

_logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Typed, env-driven configuration for the terminus platform."""

    model_config = SettingsConfigDict(env_prefix="TERMINUS_", env_file=".env")

    host: str = "127.0.0.1"
    port: int = 8000
    cookie_secure: bool = False

    # ── LLM ────────────────────────────────────────────────────────────────────
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""
    llm_model: str = "llama-3.3-70b-versatile"

    # ── Wazuh ──────────────────────────────────────────────────────────────────
    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""

    # ── Notifications ──────────────────────────────────────────────────────────
    sms_to: str = "9364992155"
    twilio_sid: str = ""
    twilio_token: str = ""
    twilio_from: str = ""
    slack_webhook: str = ""

    # ── Ticketing ──────────────────────────────────────────────────────────────
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = ""

    # ── Secrets ────────────────────────────────────────────────────────────────
    license_secret: str = ""
    token_secret: str = ""

    def model_post_init(self, __context: object) -> None:
        """Auto-generate ephemeral secrets when none are configured."""
        if not self.license_secret:
            object.__setattr__(self, "license_secret", secrets.token_hex(32))
            _logger.warning(
                "TERMINUS_LICENSE_SECRET not set — using ephemeral in-memory secret. "
                "Set it in .env for production.",
            )
        if not self.token_secret:
            object.__setattr__(self, "token_secret", secrets.token_hex(32))
            _logger.warning(
                "TERMINUS_TOKEN_SECRET not set — using ephemeral in-memory secret. "
                "Set it in .env for production.",
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached singleton of the application settings."""
    return Settings()


def reset_settings() -> None:
    """Clear the cached settings instance. Used in tests."""
    get_settings.cache_clear()
