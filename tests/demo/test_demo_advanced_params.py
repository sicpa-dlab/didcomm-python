import pytest as pytest

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.message import Message
from didcomm.pack_encrypted import (
    PackEncryptedConfig,
    PackEncryptedParameters,
    pack_encrypted,
)
from didcomm.protocols.routing.forward import unpack_forward
from didcomm.unpack import unpack, UnpackConfig
from tests.test_vectors.common import ALICE_DID, BOB_DID


@pytest.mark.asyncio
async def test_demo_advanced_parameters(
    resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
):
    # ALICE
    pack_config = PackEncryptedConfig(
        protect_sender_id=True,
        forward=True,
        enc_alg_anon=AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
    )
    # TODO replace hard-coded values
    pack_parameters = PackEncryptedParameters(
        forward_headers={"expires_time": 99999},
        forward_service_id="did:example:123456789abcdefghi#didcomm-1",
    )
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
        frm="did:example:alice#key-p256-1",
        sign_frm="did:example:alice#key-2",
        to="did:example:bob#key-p256-1",
        pack_config=pack_config,
        pack_params=pack_parameters,
    )
    packed_msg = pack_result.packed_msg
    print(f"Sending {packed_msg} to {pack_result.service_metadata.service_endpoint}")

    # BOB MEDIATOR
    forward_bob = await unpack_forward(resolvers_config_mediator1, packed_msg, True)
    packed_msg = forward_bob.forwarded_msg
    print(f"Sending {packed_msg} to Bob")

    # BOB
    unpack_config = UnpackConfig(
        expect_decrypt_by_all_keys=False, unwrap_re_wrapping_forward=False
    )
    unpack_result = await unpack(
        resolvers_config=resolvers_config_bob,
        packed_msg=packed_msg,
        unpack_config=unpack_config,
    )
    print(
        f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}"
    )
