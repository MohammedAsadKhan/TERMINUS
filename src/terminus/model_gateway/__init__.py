"""Named model connection registry."""

from terminus.model_gateway.models import (
    CLOUD_PROVIDER_URLS,
    ModelConnectionCreate,
    ModelConnectionUpdate,
    ModelConnectionView,
    Provider,
)
from terminus.model_gateway.secrets import CredentialCipher, CredentialProtectionError
from terminus.model_gateway.store import (
    ConnectionConflictError,
    ConnectionDeniedError,
    ConnectionNotFoundError,
    ConnectionUnavailableError,
    ConnectionValidationError,
    ModelConnectionStore,
)

__all__ = [
    "CLOUD_PROVIDER_URLS",
    "ConnectionConflictError",
    "ConnectionDeniedError",
    "ConnectionNotFoundError",
    "ConnectionUnavailableError",
    "ConnectionValidationError",
    "CredentialCipher",
    "CredentialProtectionError",
    "ModelConnectionCreate",
    "ModelConnectionStore",
    "ModelConnectionUpdate",
    "ModelConnectionView",
    "Provider",
]
