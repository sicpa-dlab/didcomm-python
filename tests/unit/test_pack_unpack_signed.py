import copy

import pytest

from didcomm.common.types import DID_OR_DID_URL
from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_common import TEST_MESSAGE, ALICE_DID, TestVector
from tests.test_vectors.test_vectors_signed import (
    TEST_SIGNED_DIDCOMM_MESSAGE,
)
from tests.unit.common import unpack_test_vector, decode_and_remove_jws_signatures


@pytest.mark.asyncio
async def test_unpack_signed_ed25519(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[0], resolvers_config_bob)


@pytest.mark.asyncio
async def test_unpack_signed_es256(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[1], resolvers_config_bob)


@pytest.mark.asyncio
async def test_unpack_signed_es256k(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[2], resolvers_config_bob)


@pytest.mark.asyncio
async def test_pack_signed_by_did(resolvers_config_alice, resolvers_config_bob):
    await check_pack_signed(
        ALICE_DID, TEST_SIGNED_DIDCOMM_MESSAGE[0],
        resolvers_config_alice, resolvers_config_bob)


@pytest.mark.asyncio
async def test_pack_signed_by_kid_ed25519(resolvers_config_alice, resolvers_config_bob):
    test_vector = TEST_SIGNED_DIDCOMM_MESSAGE[0]
    await check_pack_signed(
        test_vector.metadata.sign_from, test_vector,
        resolvers_config_alice, resolvers_config_bob)


@pytest.mark.asyncio
async def test_pack_signed_by_kid_es256(resolvers_config_alice, resolvers_config_bob):
    test_vector = TEST_SIGNED_DIDCOMM_MESSAGE[1]
    await check_pack_signed(
        test_vector.metadata.sign_from, test_vector,
        resolvers_config_alice, resolvers_config_bob)


@pytest.mark.asyncio
async def test_pack_signed_by_kid_es256k(resolvers_config_alice, resolvers_config_bob):
    test_vector = TEST_SIGNED_DIDCOMM_MESSAGE[2]
    await check_pack_signed(
        test_vector.metadata.sign_from, test_vector,
        resolvers_config_alice, resolvers_config_bob)


async def check_pack_signed(sign_frm: DID_OR_DID_URL, test_vector: TestVector, resolvers_config_alice,
                            resolvers_config_bob):
    expected_packed_msg = test_vector.value
    expected_metadata = copy.deepcopy(test_vector.metadata)

    pack_result = await pack_signed(
        resolvers_config_alice, TEST_MESSAGE, sign_frm=sign_frm
    )
    pack_result_wo_signature = decode_and_remove_jws_signatures(pack_result.packed_msg)
    expected_result_wo_signature = decode_and_remove_jws_signatures(expected_packed_msg)
    assert pack_result_wo_signature == expected_result_wo_signature
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    expected_metadata.signed_message = pack_result.packed_msg
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata
