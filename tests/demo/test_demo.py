import pytest as pytest

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.common.resolvers import register_default_did_resolver, register_default_secrets_resolver, ResolversConfig
from didcomm.did_doc.did_resolver import DIDResolverChain
from didcomm.pack import pack, PackConfig, PackParameters, sign
from didcomm.plaintext import Plaintext, PlaintextOptionalHeaders
from didcomm.unpack import unpack, UnpackConfig
from tests.common.example_resolvers import ExampleDIDResolver, ExampleSecretsResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_auth_crypt():
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
async def test_demo_anon_crypt():
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
async def test_demo_signed():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    signed_plaintext = await sign(plaintext=plaintext, frm=ALICE_DID)
    packed_msg = signed_plaintext.to_json()
    print(f"Sending ${packed_msg}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_plaintext():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    packed_msg = plaintext.to_json()
    print(f"Sending ${packed_msg}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_signed_then_encrypted():
    register_default_did_resolver(DIDResolverChain([ExampleDIDResolver()]))
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    signed_plaintext = await sign(plaintext=plaintext, frm=ALICE_DID)
    pack_result = await pack(plaintext=signed_plaintext, frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_advanced_parameters():
    resolvers_config = ResolversConfig(
        secrets_resolver=ExampleSecretsResolver(),
        did_resolver=ExampleDIDResolver()
    )

    # ALICE
    pack_config = PackConfig(
        protect_sender_id=True,
        forward=True,
        enc_alg_anon=AnonCryptAlg.A256GCM_ECDH_ES_A256KW
    )
    pack_parameters = PackParameters(
        forward_headers=PlaintextOptionalHeaders(expires_time=99999),
        forward_service_id="service-id"
    )
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID],
                          created_time=1516269022, expires_time=1516385931)
    signed_plaintext = await sign(plaintext=plaintext, frm="alice-sign-key1",
                                  resolvers_config=resolvers_config)
    pack_result = await pack(plaintext=signed_plaintext, frm="alice-key1", to="bob-ky1",
                             pack_config=pack_config, pack_params=pack_parameters,
                             resolvers_config=resolvers_config)
    packed_msg = pack_result.packed_msg
    print(packed_msg)

    # BOB
    unpack_config = UnpackConfig(
        expect_encrypted=True,
        expect_authenticated=True,
        expect_non_repudiation=True,
        expect_anonymous_sender=True,
        expect_decrypt_by_all_keys=False,
        unwrap_re_wrapping_forward=False
    )
    unpack_result_bob = await unpack(packed_msg=packed_msg, unpack_config=unpack_config,
                                     resolvers_config=resolvers_config)
    print(unpack_result_bob.plaintext)
