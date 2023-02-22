import pytest as pytest

from didcomm import (
    Message,
    pack_encrypted,
    PackEncryptedConfig,
    pack_plaintext,
    pack_signed,
    unpack_forward,
    unpack,
)
from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID


@pytest.mark.asyncio
async def test_demo_repudiable_authenticated_encryption(
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
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
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
        resolvers_config=resolvers_config_alice,
        message=message,
        to=BOB_DID,
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
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
        pack_config=PackEncryptedConfig(),
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(
        f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}"
    )


@pytest.mark.asyncio
async def test_demo_message_to_multiple_recipients(
    resolvers_config_alice,
    resolvers_config_bob,
    resolvers_config_charlie,
    resolvers_config_mediator1,
    resolvers_config_mediator2,
):
    # ALICE
    message = Message(
        body={"aaa": 1, "bbb": 2},
        id="1234567890",
        type="my-protocol/1.0",
        frm=ALICE_DID,
        to=[BOB_DID, CHARLIE_DID],
    )

    pack_config = PackEncryptedConfig()

    pack_result_for_bob = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=BOB_DID,
        pack_config=pack_config,
    )
    packed_msg_for_bob = pack_result_for_bob.packed_msg
    print(
        f"Sending ${packed_msg_for_bob} for Bob to "
        f"${pack_result_for_bob.service_metadata.service_endpoint}"
    )

    pack_result_for_charlie = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=CHARLIE_DID,
        pack_config=pack_config,
    )
    packed_msg_for_charlie = pack_result_for_charlie.packed_msg
    print(
        f"Sending ${packed_msg_for_charlie} for Charlie to "
        f"${pack_result_for_charlie.service_metadata.service_endpoint}"
    )

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg_for_bob, True
    )
    print(f"Got {forward_bob.forwarded_msg}")

    # BOB
    unpack_result_at_bob = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)
    print(f"Bob got ${unpack_result_at_bob.message} message")

    # CHARLIE's MEDIATOR
    forward_forward_charlie = await unpack_forward(
        resolvers_config_mediator2, packed_msg_for_charlie, True
    )
    print(f"Got {forward_forward_charlie.forwarded_msg}")

    # MEDIATOR2's MEDIATOR
    forward_charlie = await unpack_forward(
        resolvers_config_mediator1, forward_forward_charlie.forwarded_msg, True
    )
    print(f"Got {forward_charlie.forwarded_msg}")

    # CHARLIE
    unpack_result_at_charlie = await unpack(
        resolvers_config_charlie, forward_charlie.forwarded_msg
    )
    print(f"Charlie got ${unpack_result_at_charlie.message} message")


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
    pack_result = await pack_plaintext(
        resolvers_config=resolvers_config_alice, message=message
    )
    print(f"Publishing ${pack_result.packed_msg}")

    # BOB
    unpack_result = await unpack(resolvers_config_bob, pack_result.packed_msg)
    print(f"Got ${unpack_result.message} message")
