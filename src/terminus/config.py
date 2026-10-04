"""Application settings loaded from environment variables.

All fields have defaults so the app boots offline with zero env vars. Secrets that are
empty at first load are auto-generated in-memory with a logged warning.
"""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, PrivateAttr
from pydantic_settings import BaseSettings, SettingsConfigDict

_logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Typed, env-driven configuration for the terminus platform."""

    model_config = SettingsConfigDict(
        env_prefix="TERMINUS_", env_file=".env", extra="ignore"
    )

    host: str = "127.0.0.1"
    port: int = 8000
    cookie_secure: bool = False
    deployment_mode: Literal["local", "hosted"] = "local"
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = Field(default="", repr=False, exclude=True)

    # ── LLM ────────────────────────────────────────────────────────────────────
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""
    llm_model: str = "openai/gpt-oss-20b"

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
    _generated_license_secret: bool = PrivateAttr(default=False)

    def model_post_init(self, __context: object) -> None:
        """Auto-generate ephemeral secrets when none are configured."""
        if bool(self.bootstrap_admin_email) != bool(self.bootstrap_admin_password):
            raise ValueError(
                "Bootstrap admin email and password must be configured together"
            )
        if self.bootstrap_admin_password and len(self.bootstrap_admin_password) < 12:
            raise ValueError(
                "Configured bootstrap password must have at least 12 characters"
            )
        if self.deployment_mode == "hosted":
            if self.bootstrap_admin_email.strip().lower() == "admin@terminus.local":
                raise ValueError("Hosted bootstrap must use a dedicated owner email")
            if not self.license_secret:
                raise ValueError(
                    "Hosted mode requires a stable TERMINUS_LICENSE_SECRET"
                )
            object.__setattr__(self, "cookie_secure", True)
        if not self.license_secret:
            self._generated_license_secret = True
            object.__setattr__(self, "license_secret", secrets.token_hex(32))
            _logger.warning(
                "TERMINUS_LICENSE_SECRET not set — generated a development secret. "
                "Local runtime retains it in SQLite; set it explicitly for hosted deployment.",
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
    settings = Settings()
    if settings._generated_license_secret and settings.deployment_mode == "local":  # noqa: SLF001
        # Preserve local licenses across restarts of the now-durable identity
        # service. Hosted deployments must supply their own signing secret.
        from terminus.storage.db import Database

        db = Database.get_instance()
        with db.transaction() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS local_runtime_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT OR IGNORE INTO local_runtime_secrets(name,value) VALUES('license_signing',?)",
                (settings.license_secret,),
            )
            row = conn.execute(
                "SELECT value FROM local_runtime_secrets WHERE name='license_signing'"
            ).fetchone()
            object.__setattr__(settings, "license_secret", row["value"])
    return settings


def reset_settings() -> None:
    """Clear the cached settings instance. Used in tests."""
    get_settings.cache_clear()
