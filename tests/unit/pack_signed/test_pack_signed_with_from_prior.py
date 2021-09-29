import pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.core.utils import is_did_url, get_did
from didcomm.message import Message, FromPrior
from didcomm.pack_signed import pack_signed, PackSignedParameters
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID
from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    ALICE_SECRET_AUTH_KEY_ED25519,
    ALICE_SECRET_AUTH_KEY_P256,
    ALICE_SECRET_AUTH_KEY_SECP256K1,
    ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
)
from tests.test_vectors.secrets.mock_secrets_resolver_charlie import (
    CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
    CHARLIE_SECRET_AUTH_KEY_ED25519,
)


class MockSecretsResolverCharlieRotatedToAlice(MockSecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
                CHARLIE_SECRET_AUTH_KEY_ED25519,
                ALICE_SECRET_AUTH_KEY_ED25519,
                ALICE_SECRET_AUTH_KEY_P256,
                ALICE_SECRET_AUTH_KEY_SECP256K1,
                ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
                ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
                ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
            ]
        )


@pytest.fixture()
def secrets_resolver_charlie_rotated_to_alice():
    return MockSecretsResolverCharlieRotatedToAlice()


@pytest.fixture()
def resolvers_config_charlie_rotated_to_alice(
    secrets_resolver_charlie_rotated_to_alice, did_resolver_with_non_secrets
):
    return ResolversConfig(
        secrets_resolver=secrets_resolver_charlie_rotated_to_alice,
        did_resolver=did_resolver_with_non_secrets,
    )


TEST_MESSAGE: Message = Message(
    id="1234567890",
    type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
    frm=ALICE_DID,
    to=[BOB_DID],
    created_time=1516269022,
    expires_time=1516385931,
    from_prior=FromPrior(
        iss=CHARLIE_DID,
        sub=ALICE_DID,
    ),
    body={"messagespecificattribute": "and its value"},
)


@pytest.mark.asyncio
async def test_pack_plaintext_with_from_prior_and_issuer_kid(
    resolvers_config_charlie_rotated_to_alice, resolvers_config_bob
):
    pack_result = await pack_signed(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=TEST_MESSAGE,
        sign_frm=ALICE_DID,
        pack_params=PackSignedParameters(
            from_prior_issuer_kid=CHARLIE_SECRET_AUTH_KEY_ED25519.kid
        ),
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == TEST_MESSAGE
    assert (
        unpack_result.metadata.from_prior_issuer_kid
        == CHARLIE_SECRET_AUTH_KEY_ED25519.kid
    )
    assert unpack_result.metadata.signed_from_prior is not None


@pytest.mark.asyncio
async def test_pack_plaintext_with_from_prior_and_no_issuer_kid(
    resolvers_config_charlie_rotated_to_alice, resolvers_config_bob
):
    pack_result = await pack_signed(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=TEST_MESSAGE,
        sign_frm=ALICE_DID,
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == TEST_MESSAGE
    assert is_did_url(unpack_result.metadata.from_prior_issuer_kid)
    assert get_did(unpack_result.metadata.from_prior_issuer_kid) == CHARLIE_DID
    assert unpack_result.metadata.signed_from_prior is not None
