import copy

import pytest

from didcomm.common.types import DID_OR_DID_URL
from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, TestVector, TEST_MESSAGE
from tests.test_vectors.didcomm_messages.test_vectors_signed import TEST_SIGNED_DIDCOMM_MESSAGE
from tests.unit.common import check_unpack_test_vector, decode_and_remove_jws_signatures


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", TEST_SIGNED_DIDCOMM_MESSAGE)
async def test_unpack_signed(test_vector, resolvers_config_bob_spec_test_vectors):
    await check_unpack_test_vector(test_vector, resolvers_config_bob_spec_test_vectors)


@pytest.mark.asyncio
async def test_pack_signed_by_did(resolvers_config_alice_spec_test_vectors, resolvers_config_bob_spec_test_vectors):
    await check_pack_signed(
        ALICE_DID,
        TEST_SIGNED_DIDCOMM_MESSAGE[0],
        resolvers_config_alice_spec_test_vectors,
        resolvers_config_bob_spec_test_vectors,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("test_vector", TEST_SIGNED_DIDCOMM_MESSAGE)
async def test_pack_signed_by_kid(test_vector, resolvers_config_alice_spec_test_vectors, resolvers_config_bob_spec_test_vectors):
    await check_pack_signed(
        test_vector.metadata.sign_from,
        test_vector,
        resolvers_config_alice_spec_test_vectors,
        resolvers_config_bob_spec_test_vectors,
    )


async def check_pack_signed(
        sign_frm: DID_OR_DID_URL,
        test_vector: TestVector,
        resolvers_config_alice,
        resolvers_config_bob,
):
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
