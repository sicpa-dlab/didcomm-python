import pytest as pytest

from didcomm.core.serialization import dict_to_json
from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.protocols.routing.forward import unpack_forward, wrap_in_forward
from didcomm.unpack import unpack, UnpackConfig
from tests.test_vectors.common import ALICE_DID, BOB_DID


@pytest.mark.asyncio
async def test_demo_mediator(
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
    print(
        f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}"
    )

    # BOB MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, pack_result.packed_msg, True
    )
    print(f"Sending ${forward_bob.forwarded_msg} to Bob")

    # BOB
    unpack_result_bob = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Got ${unpack_result_bob.message} message")


@pytest.mark.asyncio
async def test_demo_mediators_unknown_to_sender(
    resolvers_config_alice,
    resolvers_config_bob,
    resolvers_config_mediator1,
    resolvers_config_mediator2,
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
    print(
        f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}"
    )

    # BOB MEDIATOR 1: re-wrap to a new mediator
    forward_bob_1 = await unpack_forward(
        resolvers_config_mediator1, pack_result.packed_msg, True
    )

    forward_bob_2 = await wrap_in_forward(
        resolvers_config=resolvers_config_mediator1,
        packed_msg=forward_bob_1.forwarded_msg,
        to=forward_bob_1.forward_msg.body.next,
        routing_keys=["did:example:mediator2"],
        headers={"expires_time": 99999},
    )
    print(f"Sending ${forward_bob_2} to Bob Mediator 2")

    # BOB MEDIATOR 2
    forward_bob = await unpack_forward(
        resolvers_config_mediator2, dict_to_json(forward_bob_2.msg_encrypted.msg), True
    )
    print(f"Sending ${forward_bob.forwarded_msg} to Bob")

    # BOB
    unpack_result_bob = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Got ${unpack_result_bob.message} message")


@pytest.mark.asyncio
async def test_demo_re_wrap_to_receiver(
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
    print(
        f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}"
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
    print(f"Sending ${new_packed_forward_bob} to Bob")

    # BOB
    unpack_result_bob = await unpack(
        resolvers_config_bob,
        dict_to_json(new_packed_forward_bob.msg_encrypted.msg),
        unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
    )
    print(f"Got ${unpack_result_bob.message} message")
