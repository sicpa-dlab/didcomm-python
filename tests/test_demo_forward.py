import pytest as pytest

from didcomm.did_doc.did_resolver import register_default_did_resolver, DIDResolverChain
from didcomm.pack import Packer
from didcomm.plaintext import Plaintext
from didcomm.protocols.forward.forward import Forwarder
from didcomm.secrets.secrets_resolver import register_default_secrets_resolver
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_forward():
    register_default_did_resolver(
        DIDResolverChain([TestDIDResolver()])
    )
    register_default_secrets_resolver(TestSecretsResolver())

    # ALICE
    msg = Plaintext(body={"aaa": 1, "bbb": 2}, id="1234567890", type="my-protocol/1.0",
                    frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                    created_time=1516269022, expires_time=1516385931,
                    typ="application/didcomm-plain+json")
    pack_result = await Packer(forward=True).auth_crypt(msg=msg)
    packed_forward_msg_bob = pack_result.packed_forward_msgs[BOB_DID]
    packed_forward_msg_carol = pack_result.packed_forward_msgs[CAROL_DID]
    if packed_forward_msg_bob is not None:
        print(f"Sending ${packed_forward_msg_bob.packed_forward_msg} to Bob's Mediator")
    if packed_forward_msg_carol is not None:
        print(f"Sending ${packed_forward_msg_carol.packed_forward_msg} to Carol's Mediator")

    # BOB MEDIATOR: use `unpack_forward`
    forward_bob = await Forwarder().unpack_forward(packed_forward_msg_bob.packed_forward_msg)
    print(f"Sending ${forward_bob.forwarded_msg} to Bob")

    # BOB
    unpack_result_bob = await Unpacker().unpack(forward_bob.forwarded_msg)
    print(unpack_result_bob.plaintext)

    # CAROL MEDIATOR: use `unpack` and `parse_forward`
    forward_carol_unpack_result = await Unpacker(unpack_opts=Forwarder.build_forward_unpack_opts()) \
        .unpack(packed_forward_msg_carol.packed_forward_msg)
    forward_carol_unpack_plaintext = forward_carol_unpack_result.plaintext
    if Forwarder.is_forward(forward_carol_unpack_plaintext):
        forward_carol = Forwarder.parse_forward(forward_carol_unpack_plaintext)
        print(f"Sending ${forward_carol.forwarded_msg} to Carol")

    # CAROL
    unpack_result_carol = await Unpacker().unpack(forward_carol.forwarded_msg)
    print(unpack_result_carol.plaintext)
