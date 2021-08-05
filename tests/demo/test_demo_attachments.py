import pytest as pytest

from didcomm.did_doc.did_resolver import register_default_did_resolver, DIDResolverChain
from didcomm.pack import pack
from didcomm.plaintext import Plaintext, Attachment, AttachmentDataJson
from didcomm.secrets.secrets_resolver import register_default_secrets_resolver
from didcomm.unpack import unpack
from tests.common.example_resolvers import ExampleSecretsResolver, ExampleDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"


@pytest.mark.asyncio
async def test_demo_attachments():
    register_default_did_resolver(
        DIDResolverChain([ExampleDIDResolver()])
    )
    register_default_secrets_resolver(ExampleSecretsResolver())

    # ALICE
    attachment = Attachment(id="123",
                            data=AttachmentDataJson(
                                json={"foo": "bar"}
                            ),
                            description="foo attachment",
                            mime_type="application/json")
    plaintext = Plaintext(body={"aaa": 1, "bbb": 2},
                          id="1234567890", type="my-protocol/1.0",
                          frm=ALICE_DID, to=[BOB_DID],
                          created_time=1516269022, expires_time=1516385931,
                          attachments=[attachment])
    pack_result = await pack(plaintext=plaintext, frm=ALICE_DID, to=BOB_DID)
    print(pack_result.packed_msg)

    # BOB
    unpack_result_bob = await unpack(pack_result.packed_msg)
    print(unpack_result_bob.plaintext)
