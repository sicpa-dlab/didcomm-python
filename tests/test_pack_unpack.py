import pytest as pytest

from didcomm.pack import Packer, AnonCryptAlg
from didcomm.plaintext import Plaintext
from didcomm.unpack import Unpacker, UnpackOpts
from tests.common.interfaces_test import TestSecretsResolver, TestDIDResolver

ALICE_DID = "did:example:alice"
BOB_DID = "did:example:bob"
CAROL_DID = "did:example:carol"

PAYLOAD = {"aaa": 1, "bbb": 2}


class PlaintextMessage:
    pass


@pytest.fixture()
def message():
    return Plaintext(body=PAYLOAD, id="1234567890", type="my-protocol/1.0",
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
async def test_authcrypt(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.auth_crypt(msg=message)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_anoncrypt(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.anon_crypt(msg=message, enc_alg=AnonCryptAlg.A256GCM_ECDH_ES_A256KW)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_signed(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.sign(msg=message)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_plain(packer, unpacker_bob, unpacker_carol, message):
    unpack_result_bob = await unpacker_bob.unpack(message)
    unpack_result_carol = await unpacker_carol.unpack(message)


@pytest.mark.asyncio
async def test_anoncrypt_authcrypt(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.anon_auth_crypt(msg=message, enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_anoncrypt_signed(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.anon_crypt_signed(msg=message, enc_alg=AnonCryptAlg.XC20P_ECDH_ES_A256KW)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_authcrypt_signed(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.auth_crypt_signed(msg=message)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)


@pytest.mark.asyncio
async def test_anoncrypt_authcrypt_signed(packer, unpacker_bob, unpacker_carol, message):
    packed_msg = await packer.anon_auth_crypt_signed(msg=message, enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW)
    unpack_result_bob = await unpacker_bob.unpack(packed_msg)
    unpack_result_carol = await unpacker_carol.unpack(packed_msg)
