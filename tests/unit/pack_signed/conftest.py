import pytest


@pytest.fixture()
def resolvers_config_alice(resolvers_config_alice_with_non_secrets):
    return resolvers_config_alice_with_non_secrets


@pytest.fixture()
def resolvers_config_bob(resolvers_config_bob_with_non_secrets):
    return resolvers_config_bob_with_non_secrets


@pytest.fixture()
def did_resolver(did_resolver_with_non_secrets):
    return did_resolver_with_non_secrets
