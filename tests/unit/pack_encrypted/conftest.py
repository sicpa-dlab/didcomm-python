import pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    MockSecretsResolverAlice,
)
from tests.test_vectors.secrets.mock_secrets_resolver_charlie import (
    MockSecretsResolverCharlie,
)


@pytest.fixture()
def resolvers_config_alice(resolvers_config_alice_with_non_secrets):
    return resolvers_config_alice_with_non_secrets


@pytest.fixture()
def resolvers_config_bob(resolvers_config_bob_with_non_secrets):
    return resolvers_config_bob_with_non_secrets


@pytest.fixture()
def did_resolver(did_resolver_with_non_secrets):
    return did_resolver_with_non_secrets


class MockSecretsResolverAliceNewDid(SecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=list(MockSecretsResolverAlice()._secrets.values())
            + list(MockSecretsResolverCharlie()._secrets.values())
        )


@pytest.fixture()
def secrets_resolver_alice_with_new_did():
    return MockSecretsResolverAliceNewDid()


@pytest.fixture()
def resolvers_config_alice_with_new_did(
    resolvers_config_alice, secrets_resolver_alice_with_new_did
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice_with_new_did,
        did_resolver=resolvers_config_alice.did_resolver,
    )
