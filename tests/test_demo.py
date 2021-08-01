import pytest as pytest

from didcomm.pack import Packer
from didcomm.types.plaintext import Plaintext
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_authcrypt():
    # ALICE
    body = {"aaa": 1, "bbb": 2}
    plaintext = Plaintext(body=body, id="1234567890", type="my-protocol/1.0",
                    frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                    created_time=1516269022, expires_time=1516385931,
                    typ="application/didcomm-plain+json")
    packer = Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    message = await packer.auth_crypt(plaintext=plaintext, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])

    # BOB
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_bob = await unpacker.unpack(message)

    # CAROL
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_carol = await unpacker.unpack(message)
