import pytest

from didcomm.core.serialization import json_str_to_dict
from didcomm.pack_plaintext import pack_plaintext
from didcomm.unpack import unpack
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_plaintext import (
    PLAINTEXT_EXPECTED_METADATA,
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE,
)


@pytest.mark.asyncio
async def test_unpack_simple_plaintext(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == TEST_MESSAGE


@pytest.mark.asyncio
async def test_pack_simple_plaintext(resolvers_config_bob):
    packed_msg = await pack_plaintext(resolvers_config_bob, TEST_MESSAGE)
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE
    )
