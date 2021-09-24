from dataclasses import replace

import pytest

from didcomm.core.defaults import DEF_ENC_ALG_AUTH
from didcomm.message import Message
from didcomm.pack_encrypted import PackEncryptedConfig, pack_encrypted
from didcomm.protocols.routing.forward import unpack_forward
from didcomm.unpack import unpack
from tests.test_vectors.common import ALICE_DID, BOB_DID, CHARLIE_DID


@pytest.mark.asyncio
async def test_message_to_multiple_recipients(
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

    pack_result_for_charlie = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=message,
        frm=ALICE_DID,
        to=CHARLIE_DID,
        pack_config=pack_config,
    )
    packed_msg_for_charlie = pack_result_for_charlie.packed_msg

    # BOB's MEDIATOR
    forward_bob = await unpack_forward(
        resolvers_config_mediator1, packed_msg_for_bob, True
    )

    # BOB
    unpack_result_at_bob = await unpack(resolvers_config_bob, forward_bob.forwarded_msg)

    # CHARLIE's MEDIATOR
    forward_forward_charlie = await unpack_forward(
        resolvers_config_mediator2, packed_msg_for_charlie, True
    )

    # MEDIATOR2's MEDIATOR
    forward_charlie = await unpack_forward(
        resolvers_config_mediator2, forward_forward_charlie.forwarded_msg, True
    )

    # CHARLIE
    unpack_result_at_charlie = await unpack(
        resolvers_config_charlie, forward_charlie.forwarded_msg
    )

    assert unpack_result_at_bob.message == message

    assert unpack_result_at_bob.metadata.encrypted
    assert unpack_result_at_bob.metadata.authenticated
    assert not unpack_result_at_bob.metadata.non_repudiation
    assert not unpack_result_at_bob.metadata.anonymous_sender
    assert unpack_result_at_bob.metadata.enc_alg_auth == DEF_ENC_ALG_AUTH
    assert unpack_result_at_bob.metadata.enc_alg_anon is None

    assert unpack_result_at_charlie.message == message

    assert unpack_result_at_charlie.metadata.encrypted
    assert unpack_result_at_charlie.metadata.authenticated
    assert not unpack_result_at_charlie.metadata.non_repudiation
    assert not unpack_result_at_charlie.metadata.anonymous_sender
    assert unpack_result_at_charlie.metadata.enc_alg_auth == DEF_ENC_ALG_AUTH
    assert unpack_result_at_charlie.metadata.enc_alg_anon is None

    assert unpack_result_at_bob.message == unpack_result_at_charlie.message
    assert replace(unpack_result_at_bob.metadata, encrypted_to=None) == \
           replace(unpack_result_at_charlie.metadata, encrypted_to=None)
