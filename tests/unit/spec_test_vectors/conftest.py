import pytest


@pytest.fixture()
def resolvers_config_alice(resolvers_config_alice_all_in_secrets):
    return resolvers_config_alice_all_in_secrets


@pytest.fixture()
def resolvers_config_bob(resolvers_config_bob_all_in_secrets):
    return resolvers_config_bob_all_in_secrets


@pytest.fixture()
def did_resolver(did_resolver_all_in_secrets):
    return did_resolver_all_in_secrets
