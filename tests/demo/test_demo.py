import pytest as pytest

from didcomm.common.resolvers import register_default_did_resolver, register_default_secrets_resolver
from didcomm.did_doc.did_resolver import DIDResolverChain
from didcomm.pack import pack, pack_public
from didcomm.plaintext import Plaintext
from didcomm.unpack import unpack
from tests.common.example_resolvers import ExampleDIDResolver, ExampleSecretsResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_repudiable_authentication_encryption():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack(plaintext=plaintext, frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_repudiable_non_authenticated_encryption():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack(plaintext=plaintext, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_non_repudiable_encryption():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack(plaintext=plaintext, frm=ALICE_DID, sign_frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)
    print(unpack_result_bob.metadata.signed_plaintext)


@pytest.mark.asyncio
async def test_demo_public_signed():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    packed_msg = await pack_public(plaintext=plaintext, sign_frm=ALICE_DID)
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)
    print(unpack_result_bob.metadata.signed_plaintext)


@pytest.mark.asyncio
async def test_demo_public_plaintext():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    packed_msg = await pack_public(plaintext=plaintext)
    print(f"Publishing ${packed_msg}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)
