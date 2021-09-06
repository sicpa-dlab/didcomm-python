import pytest

from didcomm.common.resolvers import ResolversConfig
from tests.test_vectors.mock_did_resolver import MockDIDResolver
from tests.test_vectors.mock_secrets_resolver_alice import MockSecretsResolverAlice
from tests.test_vectors.mock_secrets_resolver_bob import MockSecretsResolverBob


@pytest.fixture()
def did_resolver():
    return MockDIDResolver()


@pytest.fixture()
def secrets_resolver_alice():
    return MockSecretsResolverAlice()


@pytest.fixture()
def secrets_resolver_bob():
    return MockSecretsResolverBob()


@pytest.fixture()
def secrets_resolver_bob():
    return MockSecretsResolverBob()


@pytest.fixture()
def resolvers_config_alice(secrets_resolver_alice, did_resolver):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice, did_resolver=did_resolver
    )


@pytest.fixture()
def resolvers_config_bob(secrets_resolver_bob, did_resolver):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_bob, did_resolver=did_resolver
    )
