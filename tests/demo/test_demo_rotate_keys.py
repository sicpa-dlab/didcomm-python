import pytest as pytest

from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message, FromPrior
from didcomm.pack_encrypted import pack_encrypted
from didcomm.unpack import unpack
from tests.common.example_resolvers import ExampleSecretsResolver, ExampleDIDResolver

ALICE_DID = "did:example:alice"
ALICE_DID_NEW = "did:example:alice-new"
BOB_DID = "did:example:bob"

resolvers_config = ResolversConfig(
    secrets_resolver=ExampleSecretsResolver(),
    did_resolver=ExampleDIDResolver()
)


@pytest.mark.asyncio
async def test_demo_attachments():
    # ALICE
    frm_prior = FromPrior(iss=ALICE_DID,
                          sub=ALICE_DID_NEW)
    message = Message(body={"aaa": 1, "bbb": 2},
                      id="1234567890", type="my-protocol/1.0",
                      frm=ALICE_DID, to=[BOB_DID],
                      created_time=1516269022, expires_time=1516385931,
                      from_prior=frm_prior)
    pack_result = await pack_encrypted(message=message, frm=ALICE_DID, to=BOB_DID,
                                       resolvers_config=resolvers_config)
    packed_msg = pack_result.packed_msg
    print(f"Sending ${packed_msg} to ${pack_result.service_metadata.service_endpoint}")

    # BOB
    unpack_result = await unpack(packed_msg,
                                 resolvers_config=resolvers_config)
    print(f"Got ${unpack_result.message}")
