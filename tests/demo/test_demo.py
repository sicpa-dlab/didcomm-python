import pytest as pytest

from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.pack_plaintext import pack_plaintext
from didcomm.pack_signed import pack_signed
from didcomm.protocols.routing.forward import unpack_forward
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID


@pytest.mark.asyncio
async def test_demo_repudiable_authentication_encryption(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig()
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg, True
    )
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Got ${unpack_result.message} message")


@pytest.mark.asyncio
async def test_demo_repudiable_non_authenticated_encryption(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice, message=message, to=BOB_DID,
        pack_config=PackEncryptedConfig()
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg, True
    )
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Got ${unpack_result.message} message")


@pytest.mark.asyncio
async def test_demo_non_repudiable_encryption(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        sign_frm=ALICE_DID,
        to=BOB_DID,
        pack_config=PackEncryptedConfig()
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg, True
    )
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(
        f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}"
    )


@pytest.mark.asyncio
async def test_demo_signed_unencrypted(resolvers_config_alice, resolvers_config_bob):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )
    pack_result = await pack_signed(
        resolvers_config=resolvers_config_alice, message=message, sign_frm=ALICE_DID
    )
    packed_msg = pack_result.packed_msg
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, packed_msg)
    print(
        f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}"
    )


@pytest.mark.asyncio
async def test_demo_plaintext(resolvers_config_alice, resolvers_config_bob):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID],
    )
    packed_msg = await pack_plaintext(
        resolvers_config=resolvers_config_alice, message=message
    )
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, packed_msg)
    print(f"Got ${unpack_result.message} message")
