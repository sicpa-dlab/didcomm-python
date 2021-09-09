import pytest

from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.common import BOB_DID
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_anon_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON,
)
from tests.unit.common import check_unpack_test_vector, decode_jwe_headers


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON)
async def test_unpack_anoncrypt(test_vector, resolvers_config_bob):
    await check_unpack_test_vector(test_vector, resolvers_config_bob)


@pytest.mark.asyncio
async def test_pack_anoncrypt_recipient_as_did(
    resolvers_config_alice, resolvers_config_bob
):
    test_vector = TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON[0]
    expected_metadata = test_vector.metadata
    pack_result = await pack_encrypted(
        resolvers_config_alice,
        TEST_MESSAGE,
        to=BOB_DID,
        pack_config=PackEncryptedConfig(
            enc_alg_anon=expected_metadata.enc_alg_anon, forward=False
        ),
    )
    pack_result_headers = decode_jwe_headers(pack_result.packed_msg)
    expected_headers = decode_jwe_headers(test_vector.value)
    assert pack_result_headers == expected_headers
    assert pack_result.to_kids == expected_metadata.encrypted_to
    assert pack_result.from_kid == expected_metadata.encrypted_from
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata
