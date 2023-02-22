import pytest

from didcomm.core.utils import is_did_with_uri_fragment, get_did
from didcomm.pack_encrypted import (
    pack_encrypted,
    PackEncryptedParameters,
    PackEncryptedConfig,
)
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE_FROM_PRIOR_MINIMAL,
    TEST_MESSAGE_FROM_PRIOR,
)
from tests.test_vectors.secrets.mock_secrets_resolver_charlie import (
    CHARLIE_SECRET_AUTH_KEY_ED25519,
)


@pytest.mark.parametrize(
    "message", [TEST_MESSAGE_FROM_PRIOR_MINIMAL, TEST_MESSAGE_FROM_PRIOR]
)
@pytest.mark.asyncio
async def test_pack_encrypted_with_from_prior_and_issuer_kid(
    message,
    resolvers_config_charlie_rotated_to_alice,
    resolvers_config_bob,
):
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=message,
        to=BOB_DID,
        frm=ALICE_DID,
        pack_config=PackEncryptedConfig(forward=False),
        pack_params=PackEncryptedParameters(
            from_prior_issuer_kid=CHARLIE_SECRET_AUTH_KEY_ED25519.kid
        ),
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == message
    assert (
        unpack_result.metadata.from_prior_issuer_kid
        == CHARLIE_SECRET_AUTH_KEY_ED25519.kid
    )
    assert unpack_result.metadata.from_prior_jwt is not None


@pytest.mark.parametrize(
    "message", [TEST_MESSAGE_FROM_PRIOR_MINIMAL, TEST_MESSAGE_FROM_PRIOR]
)
@pytest.mark.asyncio
async def test_pack_encrypted_with_from_prior_and_no_issuer_kid(
    message,
    resolvers_config_charlie_rotated_to_alice,
    resolvers_config_bob,
):
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=message,
        to=BOB_DID,
        frm=ALICE_DID,
        pack_config=PackEncryptedConfig(forward=False),
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == message
    assert is_did_with_uri_fragment(unpack_result.metadata.from_prior_issuer_kid)
    assert get_did(unpack_result.metadata.from_prior_issuer_kid) == CHARLIE_DID
    assert unpack_result.metadata.from_prior_jwt is not None
