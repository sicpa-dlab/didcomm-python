import pytest as pytest

from didcomm.did_doc.did_resolver import register_default_did_resolver, DIDResolverChain
from didcomm.pack import Packer
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import register_default_secrets_resolver
from didcomm.unpack import Unpacker, UnpackOpts
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_authcrypt():
    register_default_did_resolver(
        DIDResolverChain([TestDIDResolver()])
    )
    register_default_secrets_resolver(TestSecretsResolver())

    # ALICE
    msg = Plaintext(body={"aaa": 1, "bbb": 2}, id="1234567890", type="my-protocol/1.0",
                    frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                    created_time=1516269022, expires_time=1516385931,
                    typ="application/didcomm-plain+json")
    pack_result = await Packer().auth_crypt(msg=msg)
    packed_msg = pack_result.packed_msg
    print(packed_msg)

    # BOB
    unpack_result_bob = await Unpacker().unpack(packed_msg)
    print(unpack_result_bob.plaintext)

    # CAROL
    unpacker = Unpacker(unpack_opts=UnpackOpts(expect_authenticated=True, expect_encrypted=True),
                        did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_carol = await unpacker.unpack(packed_msg)
    print(unpack_result_carol.plaintext)
