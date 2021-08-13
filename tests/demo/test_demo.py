import pytest as pytest

from didcomm.common.resolvers import register_default_did_resolver, register_default_secrets_resolver
from didcomm.did_doc.did_resolver import ChainedDIDResolver
from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted
from didcomm.pack_plaintext import pack_plaintext
from didcomm.pack_signed import pack_signed
from didcomm.unpack import unpack
from tests.common.example_resolvers import ExampleDIDResolver, ExampleSecretsResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_repudiable_authentication_encryption():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result = await unpack(packed_msg)
    print(f"Got ${unpack_result.message} message")


@pytest.mark.asyncio
async def test_demo_repudiable_non_authenticated_encryption():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack_encrypted(message=message, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result = await unpack(packed_msg)
    print(f"Got ${unpack_result.message} message")


@pytest.mark.asyncio
async def test_demo_non_repudiable_encryption():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, sign_frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result = await unpack(packed_msg)
    print(f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}")


@pytest.mark.asyncio
async def test_demo_signed_unencrypted():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack_signed(message=message, sign_frm=ALICE_DID)
    packed_msg = pack_result.packed_msg
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result = await unpack(packed_msg)
    print(f"Got ${unpack_result.message} message signed as ${unpack_result.metadata.signed_message}")


@pytest.mark.asyncio
async def test_demo_plaintext():
    register_default_did_resolver(ChainedDIDResolver([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID])
    packed_msg = await pack_plaintext(message=message)
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result = await unpack(packed_msg)
    print(f"Got ${unpack_result.message} message")
