from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator

from terminus.core.ids import UserId


class User(BaseModel):
    """User representation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: UserId
    email: str
    password_hash: str
    display_name: str
    created_at: datetime

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.lower()
        if "@" not in v or "." not in v:
            raise ValueError("Invalid email format")
        return v
