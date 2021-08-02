import pytest as pytest

from didcomm.pack import Packer
from didcomm.types.algorithms import SignAlg
from didcomm.types.attachment import Attachment, AttachmentData
from didcomm.types.from_prior import FromPrior
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

    attachment = Attachment(id="123",
                            data=AttachmentData(
                                json='{"foo":"bar"}'
                            ),
                            description="foo attachment",
                            mime_type="application/json")

    plaintext = Plaintext(id="1234567890",
                          type="my-protocol/1.0",
                          typ="application/didcomm-plain+json",
                          frm=ALICE_DID,
                          to=[BOB_DID, CAROL_DID],
                          created_time=1516269022,
                          expires_time=1516385931,
                          custom_headers={
                              "extra_header": "some value"
                          },
                          body=body,
                          attachments=[
                              attachment
                          ])

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


@pytest.mark.asyncio
async def test_demo_from_prior():
    # ALICE
    ALICE_DID_NEW = "did:example:alice-new"

    frm_prior = FromPrior(iss=ALICE_DID,
                          sub=ALICE_DID_NEW)

    plaintext = Plaintext(id="9876543210",
                          type="my-protocol/1.0",
                          typ="application/didcomm-plain+json",
                          frm=ALICE_DID_NEW,
                          frm_prior=frm_prior.as_jws(secrets_resolver=TestSecretsResolver(),
                                                     sign_alg=SignAlg.EdDSA),
                          to=[BOB_DID],
                          created_time=1516269022,
                          expires_time=1516385931)

    packer = Packer(did_resolver=TestDIDResolver(), secrets_resolver=TestSecretsResolver())
    message = await packer.auth_crypt(plaintext=plaintext, frm=ALICE_DID, to_dids=[BOB_DID])

    # BOB
    unpacker = Unpacker(unpack_opts=UnpackOpts(), did_resolver=TestDIDResolver(),
                        secrets_resolver=TestSecretsResolver())
    unpack_result_bob = await unpacker.unpack(message)
