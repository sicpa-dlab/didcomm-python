import copy
import dataclasses

import pytest

from didcomm.errors import DIDCommValueError
from didcomm.message import (
    Message,
    AttachmentDataLinks,
    AttachmentDataBase64,
    AttachmentDataJson,
)
from didcomm.pack_encrypted import pack_encrypted
from didcomm.pack_plaintext import pack_plaintext
from didcomm.pack_signed import pack_signed
from tests.test_vectors.common import ALICE_DID, BOB_DID
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    TEST_ATTACHMENT,
    TEST_ATTACHMENT_MINIMAL,
    TEST_FROM_PRIOR,
    TEST_FROM_PRIOR_MINIMAL,
)


async def check_invalid_pack_msg(msg: Message, resolvers_config_alice):
    with pytest.raises(DIDCommValueError):
        await pack_plaintext(resolvers_config_alice, msg)
    with pytest.raises(DIDCommValueError):
        await pack_signed(resolvers_config_alice, msg, ALICE_DID)
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(resolvers_config_alice, msg, BOB_DID)


def update_msg_field(field_name, value):
    msg = copy.deepcopy(TEST_MESSAGE)
    return dataclasses.replace(msg, **{field_name: value})


def update_attachment_field(attcmnt, field_name, value):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.attachments = [update_field(attcmnt, field_name, value)]
    return msg


def update_from_prior_field(from_prior, field_name, value):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.from_prior = update_field(from_prior, field_name, value)
    return msg


def update_field(msg, field_name, value):
    msg = copy.deepcopy(msg)
    return dataclasses.replace(msg, **{field_name: value})


@pytest.mark.asyncio
async def test_no_required_param(resolvers_config_alice):
    with pytest.raises(TypeError):
        Message(type="http://example.com/protocols/lets_do_lunch/1.0/proposal", body={})
    with pytest.raises(TypeError):
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        )
    with pytest.raises(TypeError):
        Message(id="1234567890", body={})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "msg",
    [
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            body={},
            created_time=1516269022,
            custom_headers=[{"id": "abc"}],
        ),
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            created_time=1516269022,
            body={},
            custom_headers=[{"type": "abc"}],
        ),
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            created_time=1516269022,
            body={},
            custom_headers=[{"body": "abc"}],
        ),
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            created_time=1516269022,
            body={},
            custom_headers=[{"created_time": 1516269022}],
        ),
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            created_time=1516269022,
            body={},
            custom_headers=[{"created_time": "1516269022"}],
        ),
    ],
)
async def test_custom_header_equals_to_default(msg, resolvers_config_alice):
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "msg",
    [
        update_msg_field("id", 123),
        update_msg_field("type", 123),
        update_msg_field("frm", 123),
        update_msg_field("to", 123),
        update_msg_field("to", [123]),
        update_msg_field("created_time", "123"),
        update_msg_field("expires_time", "123"),
        update_msg_field("please_ack", 1),
        update_msg_field("ack", 1),
        update_msg_field("thid", 1),
        update_msg_field("pthid", 1),
        update_msg_field("from_prior", {}),
        update_msg_field("attachments", {}),
        update_msg_field("attachments", [{}]),
        update_msg_field("custom_headers", {}),
    ],
)
async def test_message_invalid_types(msg, resolvers_config_alice):
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "msg",
    [
        update_msg_field("body", 123),
        update_msg_field("body", "123"),
        update_msg_field("body", []),
        update_msg_field("body", True),
    ],
)
async def test_message_invalid_body_type(msg, resolvers_config_alice):
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize("attachment", [TEST_ATTACHMENT, TEST_ATTACHMENT_MINIMAL])
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_fields",
    [
        ("id", 123),
        ("data", {}),
        ("description", 123),
        ("filename", 123),
        ("media_type", 123),
        ("format", 123),
        ("lastmod_time", "123"),
        ("byte_count", "123"),
    ],
)
async def test_message_invalid_attachemnt_fields(
    attachment, new_fields, resolvers_config_alice
):
    msg = update_attachment_field(attachment, *new_fields)
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize("from_prior", [TEST_FROM_PRIOR, TEST_FROM_PRIOR_MINIMAL])
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_fields",
    [
        ("iss", 123),
        ("iss", "#key1"),
        ("sub", 123),
        ("sub", "key2"),
        ("aud", 123),
        ("exp", "123"),
        ("nbf", "123"),
        ("iat", "123"),
        ("jti", 123),
        ("iss_kid", "123"),
        ("iss_kid", "did:example1"),
    ],
)
async def test_message_invalid_from_prior_fields(
    from_prior, new_fields, resolvers_config_alice
):
    msg = update_from_prior_field(from_prior, *new_fields)
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize("attachment", [TEST_ATTACHMENT, TEST_ATTACHMENT_MINIMAL])
@pytest.mark.parametrize(
    "links",
    [
        AttachmentDataLinks(links={}, hash="abc"),
        AttachmentDataLinks(links=[123], hash="abc"),
        AttachmentDataLinks(links=[123], hash="abc"),
        AttachmentDataLinks(links=["123"], hash=123),
        AttachmentDataLinks(links=["123"], hash="123", jws=123),
        AttachmentDataLinks(links=["123"], hash="123", jws="123"),
        AttachmentDataLinks(links=["123"], hash="123", jws=[]),
    ],
)
async def test_message_invalid_attachment_data_links(
    attachment, links, resolvers_config_alice
):
    msg = update_attachment_field(attachment, "data", links)
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize("attachment", [TEST_ATTACHMENT, TEST_ATTACHMENT_MINIMAL])
@pytest.mark.parametrize(
    "base64",
    [
        AttachmentDataBase64(base64=123),
        AttachmentDataBase64(base64="123", hash=123),
        AttachmentDataBase64(base64="123", hash="123", jws="{}"),
    ],
)
async def test_message_invalid_attachment_data_base64(
    attachment, base64, resolvers_config_alice
):
    msg = update_attachment_field(attachment, "data", base64)
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize("attachment", [TEST_ATTACHMENT, TEST_ATTACHMENT_MINIMAL])
@pytest.mark.parametrize(
    "json_data",
    [
        AttachmentDataJson(json=AttachmentDataJson(json={})),
        AttachmentDataJson(json={}, hash=123),
        AttachmentDataJson(json={}, hash="123", jws="{}"),
    ],
)
async def test_message_invalid_attachment_data_json(
    attachment, json_data, resolvers_config_alice
):
    msg = update_attachment_field(attachment, "data", json_data)
    await check_invalid_pack_msg(msg, resolvers_config_alice)
