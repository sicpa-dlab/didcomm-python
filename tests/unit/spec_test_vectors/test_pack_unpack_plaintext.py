import copy

import pytest

from didcomm.core.serialization import json_str_to_dict
from didcomm.message import (
    Attachment,
    AttachmentDataBase64,
    AttachmentDataLinks,
    AttachmentDataJson,
)
from didcomm.pack_plaintext import pack_plaintext
from didcomm.unpack import unpack
from tests.test_vectors.common import TEST_MESSAGE
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_plaintext import (
    PLAINTEXT_EXPECTED_METADATA,
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE,
    TEST_PLAINTEXT_ATTACHMENT_BASE64,
    TEST_PLAINTEXT_ATTACHMENT_LINKS,
    TEST_PLAINTEXT_ATTACHMENT_JSON,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_1,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_2,
)


@pytest.mark.asyncio
async def test_unpack_simple_plaintext(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == TEST_MESSAGE


@pytest.mark.asyncio
async def test_unpack_attachments_base64(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_BASE64)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == create_attachment_base64_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_links(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_LINKS)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == create_attachment_links_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_json(resolvers_config_bob):
    unpack_result = await unpack(resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_JSON)
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == create_attachment_json_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_multi_1(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_MULTI_1
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == create_attachment_multi_1_msg()


@pytest.mark.asyncio
async def test_unpack_attachments_multi_2(resolvers_config_bob):
    unpack_result = await unpack(
        resolvers_config_bob, TEST_PLAINTEXT_ATTACHMENT_MULTI_2
    )
    assert unpack_result.metadata == PLAINTEXT_EXPECTED_METADATA
    assert unpack_result.message == create_attachment_multi_2_msg()


@pytest.mark.asyncio
async def test_pack_simple_plaintext(resolvers_config_bob):
    packed_msg = await pack_plaintext(resolvers_config_bob, TEST_MESSAGE)
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE
    )


@pytest.mark.asyncio
async def test_pack_attachments_base64(resolvers_config_bob):
    packed_msg = await pack_plaintext(
        resolvers_config_bob, create_attachment_base64_msg()
    )
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_ATTACHMENT_BASE64
    )


@pytest.mark.asyncio
async def test_pack_attachments_links(resolvers_config_bob):
    packed_msg = await pack_plaintext(
        resolvers_config_bob, create_attachment_links_msg()
    )
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_ATTACHMENT_LINKS
    )


@pytest.mark.asyncio
async def test_pack_attachments_json(resolvers_config_bob):
    packed_msg = await pack_plaintext(
        resolvers_config_bob, create_attachment_json_msg()
    )
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_ATTACHMENT_JSON
    )


@pytest.mark.asyncio
async def test_pack_attachments_multi1(resolvers_config_bob):
    packed_msg = await pack_plaintext(
        resolvers_config_bob, create_attachment_multi_1_msg()
    )
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_ATTACHMENT_MULTI_1
    )


@pytest.mark.asyncio
async def test_pack_attachments_multi2(resolvers_config_bob):
    packed_msg = await pack_plaintext(
        resolvers_config_bob, create_attachment_multi_2_msg()
    )
    assert json_str_to_dict(packed_msg) == json_str_to_dict(
        TEST_PLAINTEXT_ATTACHMENT_MULTI_2
    )


def create_attachment_base64_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [Attachment(id="23", data=AttachmentDataBase64(base64="qwerty"))]
    return msg


def create_attachment_links_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        )
    ]
    return msg


def create_attachment_json_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataJson(json={"foo": "bar", "links": [2, 3]})
        )
    ]
    return msg


def create_attachment_multi_1_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataJson(json={"foo": "bar", "links": [2, 3]})
        ),
        Attachment(id="24", data=AttachmentDataBase64(base64="qwerty")),
        Attachment(
            id="25", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        ),
    ]
    return msg


def create_attachment_multi_2_msg():
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [
        Attachment(
            id="23", data=AttachmentDataLinks(links=["1", "2", "3"], hash="qwerty")
        ),
        Attachment(id="24", data=AttachmentDataBase64(base64="qwerty")),
        Attachment(
            id="25",
            data=AttachmentDataLinks(links=["1", "2", "3", "4"], hash="qwerty2"),
        ),
    ]
    return msg
