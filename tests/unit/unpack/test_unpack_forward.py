import pytest as pytest

from didcomm.core.serialization import dict_to_json
from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted
from didcomm.protocols.routing.forward import (
    unpack_forward,
    wrap_in_forward,
    ForwardMessage,
    is_forward,
)
from didcomm.unpack import unpack, UnpackConfig
from tests.test_vectors.common import ALICE_DID, BOB_DID


@pytest.mark.asyncio
async def test_mediator_re_wrap_anoncrypt_to_receiver(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        to=[BOB_DID],
        created_time=1516269022,
        expires_time=1516385931,
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        to=BOB_DID,
    )

    # BOB MEDIATOR 1: re-wrap to Bob
    old_forward_bob = await unpack_forward(
        resolvers_config_mediator1, pack_result.packed_msg, True
    )
    new_packed_forward_bob = await wrap_in_forward(
        resolvers_config=resolvers_config_mediator1,
        packed_msg=old_forward_bob.forwarded_msg,
        to=old_forward_bob.forward_msg.body.next,
        routing_keys=[old_forward_bob.forward_msg.body.next],
        headers={"expires_time": 99999},
    )

    # BOB
    unpack_result_bob = await unpack(
        resolvers_config_bob,
        dict_to_json(new_packed_forward_bob.msg_encrypted.msg),
        unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
    )

    assert unpack_result_bob.message == message
    assert unpack_result_bob.metadata.re_wrapped_in_forward


@pytest.mark.asyncio
async def test_mediator_re_wrap_authcrypt_to_receiver(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
        created_time=1516269022,
        expires_time=1516385931,
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=BOB_DID,
    )

    # BOB MEDIATOR 1: re-wrap to Bob
    old_forward_bob = await unpack_forward(
        resolvers_config_mediator1, pack_result.packed_msg, True
    )
    new_packed_forward_bob = await wrap_in_forward(
        resolvers_config=resolvers_config_mediator1,
        packed_msg=old_forward_bob.forwarded_msg,
        to=old_forward_bob.forward_msg.body.next,
        routing_keys=[old_forward_bob.forward_msg.body.next],
        headers={"expires_time": 99999},
    )

    # BOB
    unpack_result_bob = await unpack(
        resolvers_config_bob,
        dict_to_json(new_packed_forward_bob.msg_encrypted.msg),
        unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
    )

    assert unpack_result_bob.message == message
    assert unpack_result_bob.metadata.re_wrapped_in_forward


@pytest.mark.asyncio
async def test_unwrap_re_wrapping_forward_mode_for_no_re_wrapping(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        to=[BOB_DID],
        created_time=1516269022,
        expires_time=1516385931,
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        to=BOB_DID,
    )

    # BOB MEDIATOR 1
    unpack_result_mediator = await unpack(
        resolvers_config_mediator1,
        pack_result.packed_msg,
        unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
    )

    msg_mediator_as_dict = unpack_result_mediator.message.as_dict()
    assert is_forward(msg_mediator_as_dict)
    forward_message = ForwardMessage.from_dict(msg_mediator_as_dict)
    assert forward_message.body.next == BOB_DID
    assert not unpack_result_mediator.metadata.re_wrapped_in_forward

    # BOB
    unpack_result_bob = await unpack(
        resolvers_config_bob,
        forward_message.forwarded_msg,
        unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
    )

    assert unpack_result_bob.message == message
    assert not unpack_result_bob.metadata.re_wrapped_in_forward
