"""Trusted response capability registry; recommendations do not imply execution."""

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ResponseCapability:
    action: str
    executable: bool
    required_configuration: tuple[str, ...]
    verification: str
    recovery: str


CAPABILITIES = MappingProxyType(
    {
        "response.wazuh_ip_block": ResponseCapability(
            "response.wazuh_ip_block",
            True,  # noqa: FBT003 -- static capability descriptor
            (
                "Wazuh response credential",
                "agent 001",
                "Kali and target verification keys",
                "read-only nftables observer",
            ),
            "Independent source denial, management health and owned nftables membership",
            "Kernel expiry with independent recovery observations",
        ),
        "response.file_restore": ResponseCapability(
            "response.file_restore",
            False,  # noqa: FBT003 -- static capability descriptor
            ("Validated restoration adapter", "Trusted baseline"),
            "Compare restored content with trusted baseline",
            "Unavailable",
        ),
        "recommendation.review": ResponseCapability(
            "recommendation.review",
            False,  # noqa: FBT003 -- static capability descriptor
            (),
            "Operator evidence review",
            "No effect dispatched",
        ),
    }
)
