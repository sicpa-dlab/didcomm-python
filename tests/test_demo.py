import pytest as pytest

from didcomm.pack import Packer
from didcomm.types.message import Message
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_authcrypt():
    # ALICE
    payload = {"aaa": 1, "bbb": 2}
    msg = Message(payload=payload, id="1234567890", type="my-protocol/1.0",
                  frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                  created_time=1516269022, expires_time=1516385931,
                  typ="application/didcomm-plain+json")
    packer = Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    packed_msg = await packer.auth_crypt(msg=msg, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])

    # BOB
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_bob = await unpacker.unpack(packed_msg)

    # CAROL
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_carol = await unpacker.unpack(packed_msg)
