import copy

import pytest
from authlib.common.encoding import json_loads

from didcomm.common.utils import parse_base64url_encoded_json
from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.test_vectors.test_vectors_common import TEST_MESSAGE, ALICE_DID
from tests.test_vectors.test_vectors_signed import (
    TEST_SIGNED_DIDCOMM_MESSAGE,
)


@pytest.mark.asyncio
async def test_pack_signed(resolvers_config_alice, resolvers_config_bob):
    expected_packed_msg = TEST_SIGNED_DIDCOMM_MESSAGE[0].value
    expected_metadata = copy.deepcopy(TEST_SIGNED_DIDCOMM_MESSAGE[0].metadata)

    pack_result = await pack_signed(
        TEST_MESSAGE, sign_frm=ALICE_DID, resolvers_config=resolvers_config_alice
    )
    assert _decode_and_remove_signatures(
        pack_result.packed_msg
    ) == _decode_and_remove_signatures(expected_packed_msg)
    assert pack_result.sign_from_kid == expected_metadata.sign_from

    unpack_result = await unpack(
        pack_result.packed_msg, resolvers_config=resolvers_config_bob
    )
    expected_metadata.signed_message = pack_result.packed_msg
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_signed(resolvers_config_bob):
    packed_msg = TEST_SIGNED_DIDCOMM_MESSAGE[0].value
    expected_metadata = TEST_SIGNED_DIDCOMM_MESSAGE[0].metadata

    unpack_result = await unpack(packed_msg, resolvers_config=resolvers_config_bob)
    assert unpack_result.message == TEST_MESSAGE
    assert unpack_result.metadata == expected_metadata


def _decode_and_remove_signatures(jws: str) -> dict:
    jws = json_loads(jws)
    jws["payload"] = parse_base64url_encoded_json(jws["payload"])
    for s in jws["signatures"]:
        s["protected"] = parse_base64url_encoded_json(s["protected"])
        del s["signature"]
    return jws
