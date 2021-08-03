import pytest as pytest

from didcomm.did_doc.did_resolver import register_default_did_resolver, DIDResolverChain
from didcomm.pack import pack
from didcomm.plaintext import Plaintext, FromPrior
from didcomm.secrets.secrets_resolver import register_default_secrets_resolver
from didcomm.unpack import unpack
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
ALICE_DID_NEW = "did:example:alice-new"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_attachments():
    register_default_did_resolver(
        DIDResolverChain([TestDIDResolver()])
    )
    register_default_secrets_resolver(TestSecretsResolver())

    # ALICE
    frm_prior = FromPrior(iss=ALICE_DID,
                          sub=ALICE_DID_NEW)
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2}, id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID],
                          created_time=1516269022, expires_time=1516385931,
                          typ="application/didcomm-plain+json",
                          from_prior=frm_prior.as_jwt())
    pack_result = await pack(plaintext=plaintext)
    print(pack_result.packed_msg)

    # BOB
    unpack_result_bob = await unpack(pack_result.packed_msg)
    print(unpack_result_bob.plaintext)
