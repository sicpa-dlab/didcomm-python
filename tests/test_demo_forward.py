import pytest as pytest

from didcomm.pack import Packer
from didcomm.protocols.forward.forward import Forwarder
from didcomm.types.algorithms import AnonCryptAlg
from didcomm.types.plaintext import Plaintext
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_forward():
    # 1. Sender ALICE: pack and Forward
    (forwarded_bob_msg, forwarded_carol_msg) = await pack_and_forward_by_sender()

    # 2. BOB Mediator: wraps the payload into additional Forward
    forwarded_msg = await unpack_forwarded_and_forward_by_mediator(forwarded_bob_msg, to_did=BOB_DID)

    # 3. BOB: unpack forward and payload
    unpack_result_bob = unpack_forwarded_by_receiver(forwarded_msg)

    # 4. Carol Mediator: sends the payload as-is
    packed_msg_carol = unpack_forwarded_by_mediator(forwarded_carol_msg)

    # 5. Carol: unpack just a payload
    unpack_result_carol = unpack_by_receiver(packed_msg_carol)


async def pack_and_forward_by_sender():
    body = {"aaa": 1, "bbb": 2}
    plaintext = Plaintext(body=body, id="1234567890", type="my-protocol/1.0",
                    frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                    created_time=1516269022, expires_time=1516385931,
                    typ="application/didcomm-plain+json")
    packer = Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    message = await packer.auth_crypt(plaintext=plaintext, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])

    forwarder = Forwarder(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    forwarded_bob_msg = await forwarder.forward(
        message=message,
        to_did=BOB_DID,
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )
    forwarded_carol_msg = await forwarder.forward(
        message=message,
        to_did=CAROL_DID,
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )

    return forwarded_bob_msg, forwarded_carol_msg


async def unpack_forwarded_and_forward_by_mediator(forwarded_msg, to_did):
    unpacker_forward = Unpacker(unpack_opts=Forwarder.create_forward_unpack_opts(), did_resolver=TestDIDResolver(),
                                secrets_resolver=TestSecretsResolver())
    forward_unpack_result = await unpacker_forward.unpack(forwarded_msg)

    packed_msg = Forwarder.parse_forward_payload(forward_unpack_result)

    forwarder = Forwarder(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    return await forwarder.forward(
        message=packed_msg,
        to_did=to_did,
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )


async def unpack_forwarded_by_mediator(forwarded_msg):
    unpacker_forward = Unpacker(unpack_opts=Forwarder.create_forward_unpack_opts(), did_resolver=TestDIDResolver(),
                                secrets_resolver=TestSecretsResolver())
    forward_unpack_result = await unpacker_forward.unpack(forwarded_msg)
    return Forwarder.parse_forward_payload(forward_unpack_result)


async def unpack_by_receiver(packed_msg):
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    return await unpacker.unpack(packed_msg)


async def unpack_forwarded_by_receiver(forwarded_msg):
    forwarder = Forwarder(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    return (await forwarder.unpack_forward(forwarded_msg)).payload_unpack_result
