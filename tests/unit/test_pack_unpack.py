import pytest
from authlib.common.encoding import json_dumps, to_bytes, urlsafe_b64decode, to_unicode, json_loads

from didcomm.common.algorithms import SignAlg
from didcomm.common.resolvers import register_default_secrets_resolver, register_default_did_resolver
from didcomm.common.types import VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.message import Message
from didcomm.pack_signed import pack_signed
from didcomm.secrets.secrets_resolver import Secret
from didcomm.unpack import unpack, Metadata
from tests.common.test_resolvers import TestDIDDoc, TestDIDResolver, TestSecretsResolver


@pytest.mark.asyncio
async def test_pack_signed():
    alice_secret = Secret(
        kid="did:example:alice#key-1",
        type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps({
                "kty": "OKP",
                "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                "crv": "Ed25519",
                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
            })
        )
    )

    register_default_secrets_resolver(TestSecretsResolver([alice_secret]))

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=[],
        authentication_kids=["did:example:alice#key-1"],
        verification_methods=[VerificationMethod(
            id="did:example:alice#key-1",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
            controller="did:example:alice",
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json_dumps({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                })
            )
        )],
        didcomm_services=[]
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc]))

    message = Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=[
            "did:example:bob"
        ],
        created_time=1516269022,
        expires_time=1516385931,
        body={
            "messagespecificattribute": "and its value"
        }
    )

    pack_result = await pack_signed(message, "did:example:alice")

    actual_decoded_packed_msg_wo_signature = _decode_and_remove_signatures(pack_result.packed_msg)

    expected_packed_msg = json_dumps({
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0"
                   "eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh"
                   "bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh"
                   "dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz"
                   "YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header": {
                    "kid": "did:example:alice#key-1"
                }
            }
        ]
    })
    expected_decoded_packed_msg_wo_signature = _decode_and_remove_signatures(expected_packed_msg)

    expected_sign_from_kid = "did:example:alice#key-1"

    assert actual_decoded_packed_msg_wo_signature == expected_decoded_packed_msg_wo_signature
    assert pack_result.sign_from_kid == expected_sign_from_kid

    unpack_result = await unpack(pack_result.packed_msg)

    assert unpack_result.message == message

    expected_metadata = Metadata(
        encrypted=False,
        authenticated=False,
        non_repudiation=True,
        anonymous_sender=False,
        sign_from=expected_sign_from_kid,
        sign_alg=SignAlg.ED25519,
        signed_message=pack_result.packed_msg
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_signed():
    register_default_secrets_resolver(TestSecretsResolver([]))

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=[],
        authentication_kids=["did:example:alice#key-1"],
        verification_methods=[VerificationMethod(
            id="did:example:alice#key-1",
            type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
            controller="did:example:alice",
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json_dumps({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                })
            )
        )],
        didcomm_services=[]
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc]))

    packed_message = json_dumps({
        "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0"
                   "eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh"
                   "bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh"
                   "dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz"
                   "YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
        "signatures": [
            {
                "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                "header": {
                    "kid": "did:example:alice#key-1"
                }
            }
        ]
    })

    unpack_result = await unpack(packed_message)

    expected_message = Message(
        id="1234567890",
        typ="application/didcomm-plain+json",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=[
            "did:example:bob"
        ],
        created_time=1516269022,
        expires_time=1516385931,
        body={
            "messagespecificattribute": "and its value"
        }
    )

    assert unpack_result.message == expected_message

    expected_metadata = Metadata(
        encrypted=False,
        authenticated=False,
        non_repudiation=True,
        anonymous_sender=False,
        sign_from="did:example:alice#key-1",
        sign_alg=SignAlg.ED25519,
        signed_message=packed_message
    )

    assert unpack_result.metadata == expected_metadata


def _parse_base64url_encoded_json(base64url):
    return json_loads(to_unicode(urlsafe_b64decode(to_bytes(base64url))))


def _decode_and_remove_signatures(jws: str) -> dict:
    jws = json_loads(jws)
    jws['payload'] = _parse_base64url_encoded_json(jws['payload'])
    for s in jws['signatures']:
        s['protected'] = _parse_base64url_encoded_json(s['protected'])
        del s['signature']
    return jws
