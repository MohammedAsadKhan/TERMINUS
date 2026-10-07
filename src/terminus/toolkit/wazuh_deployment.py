"""Explicit tenant-bound Wazuh readers for a trusted worker deployment."""

from collections.abc import Mapping

from pydantic import SecretStr

from terminus.toolkit.wazuh_readers import (
    WazuhIndexerReader,
    WazuhIndexerSettings,
    WazuhManagerReader,
    WazuhManagerSettings,
)


def readers_from_environ(
    environ: Mapping[str, str],
    org_id: str,
) -> tuple[WazuhManagerReader | None, WazuhIndexerReader | None]:
    """Never grant another tenant access to deployment credentials."""
    prefix = "TERMINUS_SPECIALIST_WAZUH_"
    bound_org = environ.get(prefix + "ORG_ID", "").strip()
    if not bound_org or bound_org != org_id:
        return None, None
    tls = environ.get(prefix + "VERIFY_TLS", "true").strip().lower()
    if tls not in {"true", "false"}:
        raise ValueError("Wazuh VERIFY_TLS must be true or false")
    if tls == "false" and environ.get("TERMINUS_DEPLOYMENT_MODE", "local") != "local":
        raise ValueError("Unverified Wazuh TLS is restricted to local labs")

    def connection(kind: str) -> dict[str, object] | None:
        values = [
            environ.get(prefix + kind + "_" + key, "")
            for key in ("URL", "USER", "PASSWORD")
        ]
        if not any(values):
            return None
        if not all(values):
            raise ValueError("Incomplete Wazuh " + kind + " configuration")
        return {
            "org_id": org_id,
            kind.lower() + "_url": values[0],
            "username": SecretStr(values[1]),
            "password": SecretStr(values[2]),
            "verify_tls": tls == "true",
        }

    manager = connection("MANAGER")
    indexer = connection("INDEXER")
    return (
        WazuhManagerReader(WazuhManagerSettings.model_validate(manager))
        if manager
        else None,
        WazuhIndexerReader(WazuhIndexerSettings.model_validate(indexer))
        if indexer
        else None,
    )
