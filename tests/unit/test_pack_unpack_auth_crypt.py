import pytest

from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_auth_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH,
)
from tests.test_vectors.test_vectors_common import (
    TestVector,
    TEST_MESSAGE,
    BOB_DID,
    ALICE_DID,
)


@pytest.mark.asyncio
async def test_unpack_encrypted_authcrypt_x25519(resolvers_config_bob):
    await unpack_encrypted_authcrypt(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[0], resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_unpack_encrypted_authcrypt_signed_p256(resolvers_config_bob):
    await unpack_encrypted_authcrypt(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[1], resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_unpack_encrypted_authcrypt_signed_p521(resolvers_config_bob):
    await unpack_encrypted_authcrypt(
        TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[2], resolvers_config_bob
    )


async def unpack_encrypted_authcrypt(test_vector: TestVector, resolvers_config_bob):
    unpack_result = await unpack(
        test_vector.value, resolvers_config=resolvers_config_bob
    )
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == test_vector.metadata


@pytest.mark.asyncio
async def test_pack_encrypted_authcrypt_recipient_as_did(
    resolvers_config_alice, resolvers_config_bob
):
    pack_result = await pack_encrypted(
        TEST_MESSAGE,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig(forward=False),
        resolvers_config=resolvers_config_alice,
    )

    expected_metadata = TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[0].metadata
    assert pack_result.to_kids == expected_metadata.encrypted_to
    assert pack_result.from_kid == expected_metadata.encrypted_from
    assert pack_result.sign_from_kid is None

    unpack_result = await unpack(
        pack_result.packed_msg, resolvers_config=resolvers_config_bob
    )
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata
