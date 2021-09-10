import pytest

from didcomm.common.resolvers import ResolversConfig
from tests.test_vectors.did_doc.mock_did_resolver import (
    MockDIDResolverAllInSecrets,
    MockDIDResolverWithNonSecrets,
)
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    MockSecretsResolverAlice,
)
from tests.test_vectors.secrets.mock_secrets_resolver_bob import MockSecretsResolverBob


@pytest.fixture()
def did_resolver_all_in_secrets():
    return MockDIDResolverAllInSecrets()


@pytest.fixture()
def secrets_resolver_alice():
    return MockSecretsResolverAlice()


@pytest.fixture()
def secrets_resolver_bob():
    return MockSecretsResolverBob()


@pytest.fixture()
def resolvers_config_alice_all_in_secrets(
    secrets_resolver_alice, did_resolver_all_in_secrets
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice,
        did_resolver=did_resolver_all_in_secrets,
    )


@pytest.fixture()
def resolvers_config_bob_all_in_secrets(
    secrets_resolver_bob, did_resolver_all_in_secrets
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_bob, did_resolver=did_resolver_all_in_secrets
    )


@pytest.fixture()
def did_resolver_with_non_secrets():
    return MockDIDResolverWithNonSecrets()


@pytest.fixture()
def resolvers_config_alice_with_non_secrets(
    secrets_resolver_alice, did_resolver_with_non_secrets
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice,
        did_resolver=did_resolver_with_non_secrets,
    )


@pytest.fixture()
def resolvers_config_bob_with_non_secrets(
    secrets_resolver_bob, did_resolver_with_non_secrets
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_bob,
        did_resolver=did_resolver_with_non_secrets,
    )
