import pytest

from didcomm.common.types import DID_OR_DID_URL
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_anon_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON,
)
from tests.test_vectors.test_vectors_common import TEST_MESSAGE, BOB_DID, TestVector
from tests.unit.common import unpack_test_vector, decode_jwe_headers


@pytest.mark.asyncio
async def test_unpack_anoncrypt_xc20p(resolvers_config_bob):
    await unpack_test_vector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON[0], resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_unpack_anoncrypt_a256cbc(resolvers_config_bob):
    await unpack_test_vector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON[1], resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_unpack_anoncrypt_a256gcm(resolvers_config_bob):
    await unpack_test_vector(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON[2], resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_anoncrypt_recipient_as_did(
        resolvers_config_alice, resolvers_config_bob
):
    await check_pack_anoncrypt(
        to=BOB_DID,
        test_vector=TEST_ENCRYPTED_DIDCOMM_MESSAGE_ANON[0],
        resolvers_config_alice=resolvers_config_alice, resolvers_config_bob=resolvers_config_bob
    )


async def check_pack_anoncrypt(
        to: DID_OR_DID_URL,
        test_vector: TestVector,
        resolvers_config_alice, resolvers_config_bob):
    expected_metadata = test_vector.metadata
    pack_result = await pack_encrypted(
        resolvers_config_alice,
        TEST_MESSAGE,
        to=to,
        pack_config=PackEncryptedConfig(
            enc_alg_anon=expected_metadata.enc_alg_anon, forward=False
        ),
    )
    pack_result_headers = decode_jwe_headers(pack_result.packed_msg)
    expected_headers = decode_jwe_headers(test_vector.value)
    assert expected_headers == pack_result_headers
    assert pack_result.to_kids == expected_metadata.encrypted_to
    assert pack_result.from_kid == expected_metadata.encrypted_from
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata
