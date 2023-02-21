import pytest

from didcomm.unpack import unpack
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    minimal_msg,
    attachment_base64_msg,
    attachment_links_msg,
    attachment_json_msg,
    attachment_multi_1_msg,
    attachment_multi_2_msg, ack_msg,
)
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_plaintext import (
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE,
    PLAINTEXT_EXPECTED_METADATA,
)
from tests.test_vectors.didcomm_messages.tests.test_vectors_plaintext_positive import (
    TEST_PLAINTEXT_ATTACHMENT_BASE64,
    TEST_PLAINTEXT_ATTACHMENT_LINKS,
    TEST_PLAINTEXT_ATTACHMENT_JSON,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_1,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_2,
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_MINIMAL, TEST_PLAINTEXT_ACKS,
)


@pytest.mark.asyncio
async def test_unpack_simple_plaintext(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == TEST_MESSAGE


@pytest.mark.asyncio
async def test_unpack_simple_minimal(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_DIDCOMM_MESSAGE_MINIMAL
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == minimal_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_base64(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_BASE64)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == attachment_base64_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_links(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_LINKS)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == attachment_links_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_json(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_JSON)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == attachment_json_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_multi_1(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_MULTI_1
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == attachment_multi_1_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_multi_2(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_MULTI_2
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == attachment_multi_2_msg()

@pytest.mark.asyncio
async def test_unpack_ack(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_ACKS
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == ack_msg()
