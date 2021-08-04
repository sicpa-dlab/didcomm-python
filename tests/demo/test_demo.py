import pytest as pytest

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.did_doc.did_resolver import register_default_did_resolver, DIDResolverChain
from didcomm.pack import pack, PackConfig, PackParameters
from didcomm.plaintext import Plaintext, PlaintextOptionalHeaders
from didcomm.secrets.secrets_resolver import register_default_secrets_resolver
from didcomm.unpack import unpack, UnpackConfig
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_simple():
    register_default_did_resolver(
        DIDResolverChain([TestDIDResolver()])
    )
    register_default_secrets_resolver(TestSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID])
    pack_result = await pack(plaintext=plaintext, frm=ALICE_DID, to=BOB_DID)
    packed_msg = pack_result.packed_msg
    print(packed_msg)

    # BOB
    unpack_result_bob = await unpack(packed_msg)
    print(unpack_result_bob.plaintext)


@pytest.mark.asyncio
async def test_demo_advanced():
    register_default_did_resolver(
        DIDResolverChain([TestDIDResolver()])
    )
    register_default_secrets_resolver(TestSecretsResolver())

    # ALICE
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID],
                          created_time=1516269022, expires_time=1516385931)
    pack_config = PackConfig(
        secrets_resolver=TestSecretsResolver(),
        did_resolver=TestDIDResolver(),
        encryption=True,
        authentication=True,
        anonymous_sender=True,
        forward=True,
        enc_alg_anon=AnonCryptAlg.A256GCM_ECDH_ES_A256KW
    )
    pack_parameters = PackParameters(
        forward_headers=PlaintextOptionalHeaders(expires_time=99999),
        sign_frm="alice-DID-2"
    )
    pack_result = await pack(plaintext=plaintext, frm="alice-key1", to="bob-ky1",
                             pack_config=pack_config, pack_params=pack_parameters)
    packed_msg = pack_result.packed_msg
    print(packed_msg)

    # BOB
    unpack_config = UnpackConfig(
        secrets_resolver=TestSecretsResolver(),
        did_resolver=TestDIDResolver(),
        expect_encrypted=True,
        expect_authenticated=True,
        expect_non_repudiation=True,
        expect_anonymous_sender=True,
        expect_decrypt_by_all_keys=False,
        unwrap_re_wrapping_forward=False
    )
    unpack_result_bob = await unpack(packed_msg=packed_msg, unpack_config=unpack_config)
    print(unpack_result_bob.plaintext)
