import pytest as pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.pack_encrypted import pack_encrypted
from didcomm.plaintext import Plaintext, Attachment, AttachmentDataJson
from didcomm.unpack import unpack
from tests.common.example_resolvers import ExampleSecretsResolver, ExampleDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"

resolvers_config = ResolversConfig(
    secrets_resolver=ExampleSecretsResolver(),
    did_resolver=ExampleDIDResolver()
)


@pytest.mark.asyncio
async def test_demo_attachments():
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
    pack_result = await pack_encrypted(plaintext=plaintext, frm=ALICE_DID, to=BOB_DID,
                                       resolvers_config=resolvers_config)
    print(pack_result.packed_msg)

    # BOB
    unpack_result_bob = await unpack(pack_result.packed_msg,
                                     resolvers_config=resolvers_config)
    print(unpack_result_bob.plaintext)
