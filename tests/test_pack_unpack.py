import pytest as pytest

from didcomm.pack import Packer
from didcomm.types.algorithms import AnonCryptAlg
from didcomm.types.plaintext import Plaintext
from didcomm.types.unpack_opt import UnpackOpts
from didcomm.unpack import Unpacker
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"

BODY = {"aaa": 1, "bbb": 2}


@pytest.fixture()
def plaintext():
    return Plaintext(body=BODY, id="1234567890", type="my-protocol/1.0",
                     frm=ALICE_DID, to=[BOB_DID, CAROL_DID],
                     created_time=1516269022, expires_time=1516385931,
                     typ="application/didcomm-plain+json")


@pytest.fixture()
def packer():
    return Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())


@pytest.fixture()
def unpacker_bob():
    return Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())


@pytest.fixture()
def unpacker_carol():
    return Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())


@pytest.mark.asyncio
async def test_authcrypt(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.auth_crypt(plaintext=plaintext, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_anoncrypt(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.anon_crypt(plaintext=plaintext, to_dids=[BOB_DID, CAROL_DID],
                                      enc_alg=AnonCryptAlg.A256GCM_ECDH_ES_A256KW)
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_signed(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.sign(plaintext=plaintext, frm=ALICE_DID)
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_plain(packer, unpacker_bob, unpacker_carol, plaintext):
    unpack_result_bob = await unpacker_bob.unpack(plaintext)
    unpack_result_carol = await unpacker_carol.unpack(plaintext)


@pytest.mark.asyncio
async def test_anoncrypt_authcrypt(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.anon_auth_crypt(
        plaintext=plaintext,
        frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID],
        enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_anoncrypt_signed(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.anon_crypt_signed(
        plaintext=plaintext,
        frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID],
        enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_authcrypt_signed(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.auth_crypt_signed(plaintext=plaintext, frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID])
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_anoncrypt_authcrypt_signed(packer, unpacker_bob, unpacker_carol, plaintext):
    message = await packer.anon_auth_crypt_signed(
        plaintext=plaintext,
        frm=ALICE_DID, to_dids=[BOB_DID, CAROL_DID],
        enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW
    )
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)
