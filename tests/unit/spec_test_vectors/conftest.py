import pytest

from didcomm.common.resolvers import ResolversConfig
from tests.test_vectors.did_doc.mock_did_resolver import MockDIDResolverSpecTestVectors


@pytest.fixture()
def did_resolver_spec_test_vectors():
    return MockDIDResolverSpecTestVectors()


@pytest.fixture()
def resolvers_config_alice_spec_test_vectors(
    secrets_resolver_alice, did_resolver_spec_test_vectors
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_alice,
        did_resolver=did_resolver_spec_test_vectors,
    )


@pytest.fixture()
def resolvers_config_bob_spec_test_vectors(
    secrets_resolver_bob, did_resolver_spec_test_vectors
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_bob,
        did_resolver=did_resolver_spec_test_vectors,
    )
