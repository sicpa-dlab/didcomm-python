import pytest as pytest

from didcomm.common.resolvers import register_default_did_resolver, register_default_secrets_resolver, ResolversConfig
from didcomm.did_doc.did_resolver import ChainedDIDResolver
from didcomm.message import Message, MessageOptionalHeaders
from didcomm.pack_encrypted import pack_encrypted
from didcomm.protocols.forward.forward import unpack_forward, wrap_in_forward
from didcomm.unpack import unpack, UnpackConfig
from tests.common.example_resolvers import ExampleSecretsResolver, ExampleDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"

resolvers_config = ResolversConfig(
    secrets_resolver=ExampleSecretsResolver(),
    did_resolver=ChainedDIDResolver([ExampleDIDResolver()])
)


@pytest.mark.asyncio
async def test_demo_mediator():
    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID],
                      created_time=1516269022, expires_time=1516385931)
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID,
                                       resolvers_config=resolvers_config)
    print(f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB MEDIATOR
    forward_bob = await unpack_forward(packed_msg=pack_result.packed_msg,
                                       resolvers_config=resolvers_config)
    print(f"Sending ${forward_bob.forwarded_msg} to Bob")

    # BOB
    unpack_result_bob = await unpack(forward_bob.forwarded_msg,
                                     resolvers_config=resolvers_config)
    print(f"Got ${unpack_result_bob.message} message")


@pytest.mark.asyncio
async def test_demo_mediators_unknown_to_sender():
    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID],
                      created_time=1516269022, expires_time=1516385931)
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID)
    print(f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB MEDIATOR 1: re-wrap to a new mediator
    forward_bob_1 = await unpack_forward(pack_result.packed_msg,
                                         resolvers_config=resolvers_config)
    forward_bob_2 = await wrap_in_forward(packed_msg=forward_bob_1.forwarded_msg,
                                          routing_key_ids=["mediator2-routing-key"],
                                          forward_headers=MessageOptionalHeaders(expires_time=99999),
                                          resolvers_config=resolvers_config)
    print(f"Sending ${forward_bob_2} to Bob Mediator 2")

    # BOB MEDIATOR 2
    forward_bob = await unpack_forward(forward_bob_2,
                                       resolvers_config=resolvers_config)
    print(f"Sending ${forward_bob.forwarded_msg} to Bob")

    # BOB
    unpack_result_bob = await unpack(forward_bob.forwarded_msg,
                                     resolvers_config=resolvers_config)
    print(f"Got ${unpack_result_bob.message} message")


@pytest.mark.asyncio
async def test_demo_re_wrap_ro_receiver():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID],
                      created_time=1516269022, expires_time=1516385931)
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID,
                                       resolvers_config=resolvers_config)
    print(f"Sending ${pack_result.packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB MEDIATOR 1: re-wrap to Bob
    old_forward_bob = await unpack_forward(pack_result.packed_msg,
                                           resolvers_config=resolvers_config)
    new_packed_forward_bob = await wrap_in_forward(packed_msg=old_forward_bob.forwarded_msg,
                                                   routing_key_ids=[old_forward_bob.next],
                                                   forward_headers=MessageOptionalHeaders(expires_time=99999),
                                                   resolvers_config=resolvers_config)
    print(f"Sending ${new_packed_forward_bob} to Bob")

    # BOB
    unpack_result_bob = await unpack(new_packed_forward_bob,
                                     unpack_config=UnpackConfig(unwrap_re_wrapping_forward=True),
                                     resolvers_config=resolvers_config)
    print(f"Got ${unpack_result_bob.message} message")
