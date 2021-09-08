from typing import Optional

import pytest

from didcomm.common.types import DID_OR_DID_URL
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID, TestVector, TEST_MESSAGE
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_auth_encrypted import (
    TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH,
)
from tests.unit.common import (
    check_unpack_test_vector,
    decode_jwe_headers,
    remove_signed_msg,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH)
async def test_unpack_authcrypt(test_vector, resolvers_config_bob_spec_test_vectors):
    await check_unpack_test_vector(test_vector, resolvers_config_bob_spec_test_vectors)


@pytest.mark.asyncio
async def test_pack_authcrypt_sender_as_did_recipient_as_did(
    resolvers_config_alice_spec_test_vectors, resolvers_config_bob_spec_test_vectors
):
    await check_pack_authcrypt(
        frm=ALICE_DID,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(forward=False),
        test_vector=TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[0],
        resolvers_config_alice=resolvers_config_alice_spec_test_vectors,
        resolvers_config_bob=resolvers_config_bob_spec_test_vectors,
    )


@pytest.mark.asyncio
async def test_pack_authcrypt_signed_sender_as_kid_recipient_as_did(
    resolvers_config_alice_spec_test_vectors, resolvers_config_bob_spec_test_vectors
):
    test_vector = TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[1]
    await check_pack_authcrypt(
        frm=test_vector.metadata.encrypted_from,
        to=BOB_DID,
        sign_frm=ALICE_DID,
        pack_config=PackEncryptedConfig(forward=False),
        test_vector=test_vector,
        resolvers_config_alice=resolvers_config_alice_spec_test_vectors,
        resolvers_config_bob=resolvers_config_bob_spec_test_vectors,
    )


@pytest.mark.asyncio
async def test_pack_authcrypt_signed_protect_sender_sender_as_kid_recipient_as_did(
    resolvers_config_alice_spec_test_vectors, resolvers_config_bob_spec_test_vectors
):
    test_vector = TEST_ENCRYPTED_DIDCOMM_MESSAGE_AUTH[2]
    await check_pack_authcrypt(
        frm=test_vector.metadata.encrypted_from,
        to=BOB_DID,
        sign_frm=test_vector.metadata.sign_from,
        pack_config=PackEncryptedConfig(protect_sender_id=True, forward=False),
        test_vector=test_vector,
        resolvers_config_alice=resolvers_config_alice_spec_test_vectors,
        resolvers_config_bob=resolvers_config_bob_spec_test_vectors,
    )


async def check_pack_authcrypt(
    frm: DID_OR_DID_URL,
    to: DID_OR_DID_URL,
    sign_frm: Optional[DID_OR_DID_URL],
    pack_config: PackEncryptedConfig,
    test_vector: TestVector,
    resolvers_config_alice,
    resolvers_config_bob,
):
    expected_metadata = test_vector.metadata
    pack_result = await pack_encrypted(
        resolvers_config_alice,
        TEST_MESSAGE,
        frm=frm,
        to=to,
        sign_frm=sign_frm,
        pack_config=pack_config,
    )

    pack_result_headers = decode_jwe_headers(pack_result.packed_msg)
    expected_headers = decode_jwe_headers(test_vector.value)
    assert pack_result_headers == expected_headers
    assert pack_result.to_kids == expected_metadata.encrypted_to
    assert pack_result.from_kid == expected_metadata.encrypted_from
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    unpack_metadata_wo_signed_msg = remove_signed_msg(unpack_result.metadata)
    expected_metadata_wo_signed_msg = remove_signed_msg(expected_metadata)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_metadata_wo_signed_msg == expected_metadata_wo_signed_msg
