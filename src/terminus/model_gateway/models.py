"""Strict public contracts for tenant-scoped model connections."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, ClassVar, Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

Provider = Literal[
    "openai",
    "anthropic",
    "gemini",
    "openrouter",
    "deepseek",
    "openai_compatible",
    "local",
]

CLOUD_PROVIDER_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek": "https://api.deepseek.com",
}

_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,79}\Z")
_SECRET_MARKER = re.compile(
    r"(?i)(?:sk-(?:proj-|ant-)?[a-z0-9_-]{8,}|aiza[a-z0-9_-]{8,}|"  # noqa: ISC003
    + r"(?:api[ _-]?key|token|password|secret)[ _:=/-]+[a-z0-9_-]{8,})"
)


class _StrictContract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, allow_inf_nan=False
    )


def _validate_name(value: str) -> str:
    normalized = value.strip()
    if not _NAME.fullmatch(normalized):
        raise ValueError("name contains unsupported characters")
    if _SECRET_MARKER.search(normalized):
        raise ValueError("name must not contain credential material")
    return normalized


def _validate_models(value: list[str]) -> list[str]:
    if not value:
        raise ValueError("at least one model is required")
    if len(value) > 50:
        raise ValueError("at most 50 models are allowed")
    if any(not _MODEL_ID.fullmatch(item) for item in value):
        raise ValueError("model identifiers contain unsupported characters")
    if len(set(value)) != len(value):
        raise ValueError("model identifiers must be unique")
    return value


def _validate_secret(value: SecretStr | None) -> SecretStr | None:
    if value is None:
        return None
    secret = value.get_secret_value()
    if not secret.strip():
        raise ValueError("api_key must not be blank")
    if len(secret.encode("utf-8")) > 4096:
        raise ValueError("api_key must not exceed 4096 bytes")
    return value


def _normalize_cloud_url(provider: Provider, value: str | None) -> str | None:
    fixed = CLOUD_PROVIDER_URLS.get(provider)
    if fixed is None:
        return None
    if value is not None and value.rstrip("/") != fixed.rstrip("/"):
        raise ValueError("cloud provider endpoints cannot be overridden")
    return fixed


def _validate_local_host(hostname: str) -> None:
    if hostname == "localhost":
        return
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError as exc:
        raise ValueError(
            "local endpoints require localhost or a private IP address"
        ) from exc
    if not (address.is_loopback or address.is_private):
        raise ValueError("local endpoints require localhost or a private IP address")


def normalize_base_url(provider: Provider, value: str | None) -> str:
    """Return the canonical safe endpoint for a provider."""
    fixed = _normalize_cloud_url(provider, value)
    if fixed is not None:
        return fixed
    if value is None:
        raise ValueError("base_url is required for this provider")
    if len(value) > 2048 or value != value.strip():
        raise ValueError("base_url is invalid")
    parsed = urlsplit(value)
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("base_url must not contain credentials, query, or fragment")
    if _SECRET_MARKER.search(unquote(parsed.path)):
        raise ValueError("base_url must not contain credential material")
    if provider == "openai_compatible":
        if parsed.scheme != "https":
            raise ValueError("compatible endpoints require HTTPS")
    else:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("local endpoints require HTTP or HTTPS")
        if parsed.scheme == "http":
            _validate_local_host(parsed.hostname)
    return value.rstrip("/")


class ModelConnectionCreate(_StrictContract):
    """Create contract. Credentials are write-only."""

    name: str
    provider: Provider
    base_url: str | None = None
    models: Annotated[list[str], Field(min_length=1, max_length=50)]
    api_key: SecretStr | None = Field(default=None, repr=False, exclude=True)
    enabled: bool = False

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        return _validate_name(value)

    @field_validator("models")
    @classmethod
    def valid_models(cls, value: list[str]) -> list[str]:
        return _validate_models(value)

    @field_validator("api_key")
    @classmethod
    def valid_secret(cls, value: SecretStr | None) -> SecretStr | None:
        return _validate_secret(value)

    @model_validator(mode="after")
    def valid_endpoint(self) -> ModelConnectionCreate:
        canonical = normalize_base_url(self.provider, self.base_url)
        object.__setattr__(self, "base_url", canonical)
        return self


class ModelConnectionUpdate(_StrictContract):
    """Compare-and-swap update; omitted credentials are retained."""

    expected_version: Annotated[int, Field(ge=1)]
    name: str | None = None
    provider: Provider | None = None
    base_url: str | None = None
    models: Annotated[list[str] | None, Field(min_length=1, max_length=50)] = None
    api_key: SecretStr | None = Field(default=None, repr=False, exclude=True)
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str | None) -> str | None:
        return None if value is None else _validate_name(value)

    @field_validator("models")
    @classmethod
    def valid_models(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _validate_models(value)

    @field_validator("api_key")
    @classmethod
    def valid_secret(cls, value: SecretStr | None) -> SecretStr | None:
        return _validate_secret(value)


class ModelConnectionView(_StrictContract):
    """Read model that intentionally reveals no credential material."""

    org_id: str
    connection_id: str
    name: str
    provider: Provider
    base_url: str | None
    models: list[str]
    enabled: bool
    credential_configured: bool
    credential_mask: Literal["********"] | None
    version: Annotated[int, Field(ge=1)]
    created_at: datetime
    updated_at: datetime
    verification_status: Literal["unverified"] = "unverified"
