"""Tenant isolation and explicit deployment boundaries for Wazuh readers."""

import pytest

from terminus.toolkit.wazuh_deployment import readers_from_environ


def settings():
    return {
        "TERMINUS_SPECIALIST_WAZUH_ORG_ID": "org-lab",
        "TERMINUS_SPECIALIST_WAZUH_MANAGER_URL": "https://192.168.56.104:55000",
        "TERMINUS_SPECIALIST_WAZUH_MANAGER_USER": "manager-reader",
        "TERMINUS_SPECIALIST_WAZUH_MANAGER_PASSWORD": "fixture-manager",
        "TERMINUS_SPECIALIST_WAZUH_INDEXER_URL": "https://127.0.0.1:19200",
        "TERMINUS_SPECIALIST_WAZUH_INDEXER_USER": "indexer-reader",
        "TERMINUS_SPECIALIST_WAZUH_INDEXER_PASSWORD": "fixture-indexer",
    }


def test_unconfigured_and_foreign_tenants_have_no_readers():
    assert readers_from_environ({}, "org-lab") == (None, None)
    assert readers_from_environ(settings(), "org-other") == (None, None)


@pytest.mark.asyncio
async def test_independent_credentials_and_tls_default():
    manager, indexer = readers_from_environ(settings(), "org-lab")
    assert manager is not None
    assert indexer is not None
    try:
        assert manager.settings.username.get_secret_value() == "manager-reader"
        assert indexer.settings.username.get_secret_value() == "indexer-reader"
        assert manager.settings.verify_tls
        assert indexer.settings.verify_tls
        assert "fixture-manager" not in repr(manager.settings)
    finally:
        await manager.aclose()
        await indexer.aclose()


def test_incomplete_configuration_rejected():
    env = settings()
    del env["TERMINUS_SPECIALIST_WAZUH_MANAGER_PASSWORD"]
    with pytest.raises(ValueError, match="Incomplete"):
        readers_from_environ(env, "org-lab")


def test_hosted_cannot_disable_tls():
    env = settings()
    env.update(
        TERMINUS_SPECIALIST_WAZUH_VERIFY_TLS="false", TERMINUS_DEPLOYMENT_MODE="hosted"
    )
    with pytest.raises(ValueError, match="local labs"):
        readers_from_environ(env, "org-lab")


def test_invalid_tls_and_origin_rejected():
    env = settings()
    env["TERMINUS_SPECIALIST_WAZUH_VERIFY_TLS"] = "maybe"
    with pytest.raises(ValueError):
        readers_from_environ(env, "org-lab")
    env["TERMINUS_SPECIALIST_WAZUH_VERIFY_TLS"] = "true"
    env["TERMINUS_SPECIALIST_WAZUH_MANAGER_URL"] = "http://localhost"
    with pytest.raises(ValueError):
        readers_from_environ(env, "org-lab")
