import pytest as pytest

from didcomm.pack import PackBuilder
from didcomm.types.algorithms import EncAlgAnonCrypt
from didcomm.types.message import Message
from didcomm.types.mtc import MTC
from didcomm.unpack import UnpackBuilder
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"


@pytest.mark.asyncio
async def test_demo_anoncrypt_authcrypt_signed():
    # ALICE
    payload = {"aaa": 1, "bbb": 2}
    msg = Message.build(payload=payload, id="1234567890", type="my-protocol/1.0") \
        .frm(ALICE_DID) \
        .to([BOB_DID, CAROL_DID]) \
        .created_time(1516269022) \
        .expires_time(1516385931) \
        .typ("application/didcomm-plain+json") \
        .finalize()
    packed_msg = await PackBuilder(msg) \
        .did_resolver(TestDIDResolver()) \
        .secrets_resolver(TestSecretsResolver()) \
        .sign_from_did(from_did=ALICE_DID) \
        .auth_crypt_from_did(from_did=ALICE_DID, to_dids=[BOB_DID, CAROL_DID]) \
        .anon_crypt(to_dids=[BOB_DID, CAROL_DID], enc=EncAlgAnonCrypt.XC20P) \
        .pack()

    # BOB
    unpack_result_bob = await UnpackBuilder() \
        .did_resolver(TestDIDResolver()) \
        .secrets_resolver(TestSecretsResolver()) \
        .mtc(MTC.build().finalize()) \
        .unpack(packed_msg)

    # CAROL
    unpack_result_carol = await UnpackBuilder() \
        .did_resolver(TestDIDResolver()) \
        .secrets_resolver(TestSecretsResolver()) \
        .mtc(MTC.build().finalize()) \
        .unpack(packed_msg)
