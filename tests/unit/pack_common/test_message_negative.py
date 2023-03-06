import copy
import dataclasses

import attr
import attrs
import pytest

from didcomm.errors import DIDCommValueError
from didcomm.message import (
    Message,
    AttachmentDataLinks,
    AttachmentDataBase64,
    AttachmentDataJson,
    FromPrior,
)
from didcomm.pack_encrypted import pack_encrypted
from didcomm.pack_plaintext import pack_plaintext
from didcomm.pack_signed import pack_signed
from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    TEST_ATTACHMENT,
    TEST_ATTACHMENT_MINIMAL,
    TEST_FROM_PRIOR,
    TEST_FROM_PRIOR_MINIMAL,
)


async def check_invalid_pack_msg(msg: Message, resolvers_config_alice):
    # TODO all these pack API will fail at `msg.as_dict` call, likely
    #      better instead just to check that particular msg API once
    with pytest.raises(DIDCommValueError):
        await pack_plaintext(resolvers_config_alice, msg)
    with pytest.raises(DIDCommValueError):
        await pack_signed(resolvers_config_alice, msg, ALICE_DID)
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(resolvers_config_alice, msg, BOB_DID)


def update_attachment_field(attcmnt, field_name, value):
    msg = copy.deepcopy(TEST_MESSAGE)
    attcmnt = copy.deepcopy(attcmnt)
    attrs.evolve(attcmnt, **{field_name: value})
    msg.attachments = [attcmnt]
    return msg


def update_from_prior_field(from_prior, field_name, value):
    msg = copy.deepcopy(TEST_MESSAGE)
    from_prior = copy.deepcopy(from_prior)
    # to hack / workaround FromPrior frozen setting
    object.__setattr__(from_prior, field_name, value)
    msg.from_prior = from_prior
    return msg


def update_field(msg, field_name, value):
    msg = copy.deepcopy(msg)
    if dataclasses.is_dataclass(msg):
        return dataclasses.replace(msg, **{field_name: value})
    elif attr.has(type(msg)):
        return attr.evolve(msg, **{field_name: value})
    else:
        raise TypeError(f"unexpected type `{type(msg)}`")


def update_msg_field(field_name, value):
    return update_field(TEST_MESSAGE, field_name, value)


@pytest.mark.asyncio
async def test_no_required_param(resolvers_config_alice):
    with pytest.raises(TypeError):
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        )
    with pytest.raises(TypeError):
        Message(id="1234567890", body={})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "custom_header",
    [
        [{"id": "abc"}],
        [{"type": "abc"}],
        [{"body": "abc"}],
        [{"created_time": 1516269022}],
        [{"created_time": "1516269022"}],
    ],
)
async def test_custom_header_equals_to_default(custom_header):
    with pytest.raises(DIDCommValueError):
        Message(
            id="1234567890",
            type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
            created_time=1516269022,
            custom_headers=custom_header,
            body={},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "new_fields",
    [
        ("type", 123),
        ("frm", 123),
        ("to", 123),
        ("to", [123]),
        ("created_time", "123"),
        ("expires_time", "123"),
        ("please_ack", 1),
        ("ack", 1),
        ("thid", 1),
        ("pthid", 1),
        ("from_prior", {}),
        ("attachments", {}),
        ("attachments", [{}]),
        ("custom_headers", {}),
    ],
)
async def test_message_invalid_types(new_fields):
    with pytest.raises(DIDCommValueError):
        update_field(TEST_MESSAGE, *new_fields)


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
    with pytest.raises(DIDCommValueError):
        update_attachment_field(attachment, *new_fields)


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
    ],
)
async def test_message_invalid_from_prior_fields(
    from_prior, new_fields, resolvers_config_alice
):
    msg = update_from_prior_field(from_prior, *new_fields)
    await check_invalid_pack_msg(msg, resolvers_config_alice)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "iss, sub",
    [
        ("invalid", ALICE_DID),
        (CHARLIE_DID, "invalid"),
    ],
)
async def test_message_invalid_from_prior_construction(iss, sub):
    with pytest.raises(DIDCommValueError):
        FromPrior(iss, sub)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "links, hashh, jws",
    [
        ({}, "abc", None),
        ([123], "abc", None),
        ([123], "abc", None),
        (["123"], 123, None),
        (["123"], "123", 123),
        (["123"], "123", "123"),
        (["123"], "123", []),
    ],
)
async def test_message_invalid_attachment_data_links(links, hashh, jws):
    with pytest.raises(DIDCommValueError):
        AttachmentDataLinks(links, hashh, jws)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base64, hashh, jws",
    [
        (123, None, None),
        ("123", 123, None),
        ("123", "123", "{}"),
    ],
)
async def test_message_invalid_attachment_data_base64(base64, hashh, jws):
    with pytest.raises(DIDCommValueError):
        AttachmentDataBase64(base64, hashh, jws)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "json_data, hashh, jws",
    [
        (AttachmentDataJson(json={}), None, None),
        ({}, 123, None),
        ({}, "123", "{}"),
    ],
)
async def test_message_invalid_attachment_data_json(json_data, hashh, jws):
    with pytest.raises(DIDCommValueError):
        AttachmentDataJson(json_data, hashh, jws)
