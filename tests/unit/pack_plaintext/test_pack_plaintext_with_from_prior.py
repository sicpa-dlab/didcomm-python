import pytest

from didcomm.core.serialization import json_str_to_dict
from didcomm.core.utils import get_did, is_did_with_uri_fragment
from didcomm.pack_plaintext import pack_plaintext, PackPlaintextParameters
from didcomm.unpack import unpack
from tests.test_vectors.common import (
    CHARLIE_DID,
)
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
async def test_pack_plaintext_with_from_prior_and_issuer_kid(
    message,
    resolvers_config_charlie_rotated_to_alice,
    resolvers_config_bob,
):
    pack_result = await pack_plaintext(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=message,
        pack_params=PackPlaintextParameters(
            from_prior_issuer_kid=CHARLIE_SECRET_AUTH_KEY_ED25519.kid
        ),
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == message
    assert (
        unpack_result.metadata.from_prior_issuer_kid
        == CHARLIE_SECRET_AUTH_KEY_ED25519.kid
    )
    assert (
        unpack_result.metadata.from_prior_jwt
        == json_str_to_dict(pack_result.packed_msg)["from_prior"]
    )


@pytest.mark.parametrize(
    "message", [TEST_MESSAGE_FROM_PRIOR_MINIMAL, TEST_MESSAGE_FROM_PRIOR]
)
@pytest.mark.asyncio
async def test_pack_plaintext_with_from_prior_and_no_issuer_kid(
    message,
    resolvers_config_charlie_rotated_to_alice,
    resolvers_config_bob,
):
    pack_result = await pack_plaintext(
        resolvers_config=resolvers_config_charlie_rotated_to_alice,
        message=message,
    )
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)

    assert unpack_result.message == message
    assert is_did_with_uri_fragment(unpack_result.metadata.from_prior_issuer_kid)
    assert get_did(unpack_result.metadata.from_prior_issuer_kid) == CHARLIE_DID
    assert (
        unpack_result.metadata.from_prior_jwt
        == json_str_to_dict(pack_result.packed_msg)["from_prior"]
    )
