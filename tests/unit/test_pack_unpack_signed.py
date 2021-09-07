import copy

import pytest

from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_common import TEST_MESSAGE, ALICE_DID
from tests.test_vectors.test_vectors_signed import (
    TEST_SIGNED_DIDCOMM_MESSAGE,
)
from tests.unit.common import decode_and_remove_signatures, unpack_test_vector


@pytest.mark.asyncio
async def test_pack_signed(resolvers_config_alice, resolvers_config_bob):
    expected_packed_msg = TEST_SIGNED_DIDCOMM_MESSAGE[0].value
    expected_metadata = copy.deepcopy(TEST_SIGNED_DIDCOMM_MESSAGE[0].metadata)

    pack_result = await pack_signed(
        resolvers_config_alice, TEST_MESSAGE, sign_frm=ALICE_DID
    )
    pack_result_wo_signature = decode_and_remove_signatures(pack_result.packed_msg)
    expected_result_wo_signature = decode_and_remove_signatures(expected_packed_msg)
    assert pack_result_wo_signature == expected_result_wo_signature
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    expected_metadata.signed_message = pack_result.packed_msg
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_signed_ed25519(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[0], resolvers_config_bob)


@pytest.mark.asyncio
async def test_unpack_signed_es256(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[1], resolvers_config_bob)


@pytest.mark.asyncio
async def test_unpack_signed_es256k(resolvers_config_bob):
    await unpack_test_vector(TEST_SIGNED_DIDCOMM_MESSAGE[2], resolvers_config_bob)
