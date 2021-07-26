import pytest as pytest

from didcomm.pack import Packer
from didcomm.protocols.forward.forward import Forwarder
from didcomm.types.algorithms import AnonCryptAlg
from didcomm.types.message import Message
from didcomm.types.mtc import MTC
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_forward():
    # ALICE
    payload = {"aaa": 1, "bbb": 2}
    msg = Message(payload=payload, id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                  created_time=1516269022, expires_time=1516385931,
                  typ="application/didcomm-plain+json")
    packer = Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    packed_msg = await packer.auth_crypt(msg=msg, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])

    forwarder = Forwarder(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    forwarded_bob_msg = await forwarder.forward(
        packed_msg=packed_msg,
        to_did=BOB_DID,
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )
    forwarded_carol_msg = await forwarder.forward(
        packed_msg=packed_msg,
        to_did=CAROL_DID,
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )

    # BOB Mediator
    unpacker_forward = Unpacker(mtc=Forwarder.create_forward_mtc(), did_resolver=TestDIDResolver(),
                                secrets_resolver=TestSecretsResolver())
    forward_bob_unpack_result = await unpacker_forward.unpack(forwarded_bob_msg)
    packed_msg_bob = Forwarder.parse_forward_payload(forward_bob_unpack_result)

    # BOB
    unpacker = Unpacker(mtc=MTC(), did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    unpack_result_bob = await unpacker.unpack(packed_msg_bob)

    # Carol Mediator
    unpacker_forward = Unpacker(mtc=Forwarder.create_forward_mtc(), did_resolver=TestDIDResolver(),
                                secrets_resolver=TestSecretsResolver())
    forward_carol_unpack_result = await unpacker_forward.unpack(forwarded_bob_msg)
    packed_msg_bob = Forwarder.parse_forward_payload(forward_bob_unpack_result)

    # BOB
    unpacker = Unpacker(mtc=MTC(), did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    unpack_result_carol = await unpacker.unpack(packed_msg_bob)
