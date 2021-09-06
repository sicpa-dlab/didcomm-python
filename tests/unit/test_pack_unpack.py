import pytest
from authlib.common.encoding import json_dumps, json_loads

from didcomm.common.algorithms import SignAlg, AnonCryptAlg, AuthCryptAlg
from didcomm.common.resolvers import (
    register_default_secrets_resolver,
    register_default_did_resolver,
)
from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.common.utils import parse_base64url_encoded_json
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.message import Message
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
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
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                    "crv": "Ed25519",
                    "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                }
            ),
        ),
    )

    register_default_secrets_resolver(TestSecretsResolver([alice_secret]))

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=[],
        authentication_kids=["did:example:alice#key-1"],
        verification_methods=[
            VerificationMethod(
                id="did:example:alice#key-1",
                type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
                controller="did:example:alice",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                        }
                    ),
                ),
            )
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc]))

    message = Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    pack_result = await pack_signed(message, sign_frm="did:example:alice")

    actual_decoded_packed_msg_wo_signature = _decode_and_remove_signatures(
        pack_result.packed_msg
    )

    expected_packed_msg = json_dumps(
        {
            "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0"
            "eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh"
            "bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh"
            "dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz"
            "YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures": [
                {
                    "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                    "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                    "header": {"kid": "did:example:alice#key-1"},
                }
            ],
        }
    )
    expected_decoded_packed_msg_wo_signature = _decode_and_remove_signatures(
        expected_packed_msg
    )

    expected_sign_from_kid = "did:example:alice#key-1"

    assert (
        actual_decoded_packed_msg_wo_signature
        == expected_decoded_packed_msg_wo_signature
    )
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
        signed_message=pack_result.packed_msg,
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_signed():
    register_default_secrets_resolver(TestSecretsResolver([]))

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=[],
        authentication_kids=["did:example:alice#key-1"],
        verification_methods=[
            VerificationMethod(
                id="did:example:alice#key-1",
                type=VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
                controller="did:example:alice",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                        }
                    ),
                ),
            )
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc]))

    packed_message = json_dumps(
        {
            "payload": "eyJpZCI6IjEyMzQ1Njc4OTAiLCJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXBsYWluK2pzb24iLCJ0"
            "eXBlIjoiaHR0cDovL2V4YW1wbGUuY29tL3Byb3RvY29scy9sZXRzX2RvX2x1bmNoLzEuMC9wcm9wb3Nh"
            "bCIsImZyb20iOiJkaWQ6ZXhhbXBsZTphbGljZSIsInRvIjpbImRpZDpleGFtcGxlOmJvYiJdLCJjcmVh"
            "dGVkX3RpbWUiOjE1MTYyNjkwMjIsImV4cGlyZXNfdGltZSI6MTUxNjM4NTkzMSwiYm9keSI6eyJtZXNz"
            "YWdlc3BlY2lmaWNhdHRyaWJ1dGUiOiJhbmQgaXRzIHZhbHVlIn19",
            "signatures": [
                {
                    "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
                    "signature": "FW33NnvOHV0Ted9-F7GZbkia-vYAfBKtH4oBxbrttWAhBZ6UFJMxcGjL3lwOl4YohI3kyyd08LHPWNMgP2EVCQ",
                    "header": {"kid": "did:example:alice#key-1"},
                }
            ],
        }
    )

    unpack_result = await unpack(packed_message)

    expected_message = Message(
        id="1234567890",
        typ="application/didcomm-plain+json",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    assert unpack_result.message == expected_message

    expected_metadata = Metadata(
        encrypted=False,
        authenticated=False,
        non_repudiation=True,
        anonymous_sender=False,
        sign_from="did:example:alice#key-1",
        sign_alg=SignAlg.ED25519,
        signed_message=packed_message,
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_pack_encrypted_for_anoncrypt():
    bob_secret_1 = Secret(
        kid="did:example:bob#key-p256-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "d": "9KIW7dohB1e0IlavGTSmV6nT6l27oNvNnkdoKNcXe88",
                    "crv": "P-256",
                    "x": "z2mxGIK8jf_Pk2t3pjwUno3e9s8n8KTyWddQvP9fKas",
                    "y": "BhwSorIWrU6xAh7qPTG9DmnbuNQhuIlELZoJrnFMnv0",
                }
            ),
        ),
    )

    bob_secret_2 = Secret(
        kid="did:example:bob#key-p256-2",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "d": "RymzxQ6R8Rv04v9cOVM9Ygl2_WSZUw4isPFVDFx2htU",
                    "crv": "P-256",
                    "x": "-akiIaFTb8yQFMXuLCEnvi-_oX6uOXBKbeUXk7qRP7k",
                    "y": "PRqnktHWOk6cBPQI17pXjFVnU6K7JDdUJxeXLE8Y5Yo",
                }
            ),
        ),
    )

    register_default_secrets_resolver(TestSecretsResolver([bob_secret_1, bob_secret_2]))

    bob_did_doc = TestDIDDoc(
        did="did:example:bob",
        key_agreement_kids=["did:example:bob#key-p256-1", "did:example:bob#key-p256-2"],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:bob#key-p256-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "z2mxGIK8jf_Pk2t3pjwUno3e9s8n8KTyWddQvP9fKas",
                            "y": "BhwSorIWrU6xAh7qPTG9DmnbuNQhuIlELZoJrnFMnv0",
                        }
                    ),
                ),
            ),
            VerificationMethod(
                id="did:example:bob#key-p256-2",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "-akiIaFTb8yQFMXuLCEnvi-_oX6uOXBKbeUXk7qRP7k",
                            "y": "PRqnktHWOk6cBPQI17pXjFVnU6K7JDdUJxeXLE8Y5Yo",
                        }
                    ),
                ),
            ),
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([bob_did_doc]))

    message = Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    pack_result = await pack_encrypted(
        message,
        to="did:example:bob",
        pack_config=PackEncryptedConfig(
            enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW, forward=False
        ),
    )

    assert pack_result.to_kids == [
        "did:example:bob#key-p256-1",
        "did:example:bob#key-p256-2",
    ]
    assert pack_result.from_kid is None
    assert pack_result.sign_from_kid is None

    unpack_result = await unpack(pack_result.packed_msg)

    assert unpack_result.message == message

    expected_metadata = Metadata(
        encrypted=True,
        authenticated=False,
        non_repudiation=False,
        anonymous_sender=True,
        encrypted_to=["did:example:bob#key-p256-1", "did:example:bob#key-p256-2"],
        enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW,
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_encrypted_for_anoncrypt():
    bob_secret_1 = Secret(
        kid="did:example:bob#key-p256-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "d": "9KIW7dohB1e0IlavGTSmV6nT6l27oNvNnkdoKNcXe88",
                    "crv": "P-256",
                    "x": "z2mxGIK8jf_Pk2t3pjwUno3e9s8n8KTyWddQvP9fKas",
                    "y": "BhwSorIWrU6xAh7qPTG9DmnbuNQhuIlELZoJrnFMnv0",
                }
            ),
        ),
    )

    bob_secret_2 = Secret(
        kid="did:example:bob#key-p256-2",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "EC",
                    "d": "RymzxQ6R8Rv04v9cOVM9Ygl2_WSZUw4isPFVDFx2htU",
                    "crv": "P-256",
                    "x": "-akiIaFTb8yQFMXuLCEnvi-_oX6uOXBKbeUXk7qRP7k",
                    "y": "PRqnktHWOk6cBPQI17pXjFVnU6K7JDdUJxeXLE8Y5Yo",
                }
            ),
        ),
    )

    register_default_secrets_resolver(TestSecretsResolver([bob_secret_1, bob_secret_2]))

    bob_did_doc = TestDIDDoc(
        did="did:example:bob",
        key_agreement_kids=["did:example:bob#key-p256-1", "did:example:bob#key-p256-2"],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:bob#key-p256-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "z2mxGIK8jf_Pk2t3pjwUno3e9s8n8KTyWddQvP9fKas",
                            "y": "BhwSorIWrU6xAh7qPTG9DmnbuNQhuIlELZoJrnFMnv0",
                        }
                    ),
                ),
            ),
            VerificationMethod(
                id="did:example:bob#key-p256-2",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "EC",
                            "crv": "P-256",
                            "x": "-akiIaFTb8yQFMXuLCEnvi-_oX6uOXBKbeUXk7qRP7k",
                            "y": "PRqnktHWOk6cBPQI17pXjFVnU6K7JDdUJxeXLE8Y5Yo",
                        }
                    ),
                ),
            ),
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([bob_did_doc]))

    packed_message = json_dumps(
        {
            "ciphertext": "P9vF3kq-jyDvFXy0GcHk7m1IH3ieJLH8E8enC_ZXYWmdmkGj6F4DT0YXYCLwjU9SAE4fIbIWiz5C6xk-"
            "iz7tgQbhoFFL1O5W5NCp2xPUViqs3jI1NyxiJZFbmvIvErvFiUBy49VT7-jJfD22G-6DgrequTu7lLoh"
            "nzVbIkf0y9ckK9ycGaDuT6do0dJdxZagFP0ej4qZWJFojv227Qn32My8ohCnXOszj5Mgdbg1ad9E1JNk"
            "dwZHkow-drz4f82hccohG2pr4sf_aue2kHLpwfs7dOnujvcNMq6UIVolulk-friOCAtR84nmXDrQcI0L"
            "VEUrdgNUCGgcnX95DcbcxtAGvSiqxyWauBt4ZkUuzMBFjOKJOIkW",
            "protected": "eyJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIxc1luMDM3U2lERnBKMGQzV3VKbks5"
            "MzRxV2xUOURabEhhUy1IZTlCNzFzIiwieSI6Ik03SzZPUUNCWGwyZjU3SDFKZlZsRm9Ha3VZTVNGVHBn"
            "Mk9Zazh0Y0JXWEEifSwiYXB2Ijoiei1McXB2VlhEYl9zR1luM21qUUxwdXUyQ1FMZXdZdVpvVFdPSVhQ"
            "SDNGTSIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tZW5jcnlwdGVkK2pzb24iLCJlbmMiOiJYQzIw"
            "UCIsImFsZyI6IkVDREgtRVMrQTI1NktXIn0",
            "recipients": [
                {
                    "encrypted_key": "DEOpYs3EMN0En_5sbWIfzBTsvyeBq5xQU8LgxPJcoaUK1cB9hszdOw",
                    "header": {"kid": "did:example:bob#key-p256-1"},
                },
                {
                    "encrypted_key": "VldoeyO8s90A4BHvVAjgUdl7gJyNUoaKG-AjRumvcm40uxQYk7KjsA",
                    "header": {"kid": "did:example:bob#key-p256-2"},
                },
            ],
            "tag": "orzOQsbjcwBiR4Pu_CF0bg",
            "iv": "UxgEJcKTxP_3Hw_FRC3etaEIYBimlctx",
        }
    )

    unpack_result = await unpack(packed_message)

    expected_message = Message(
        id="1234567890",
        typ="application/didcomm-plain+json",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    assert unpack_result.message == expected_message

    expected_metadata = Metadata(
        encrypted=True,
        authenticated=False,
        non_repudiation=False,
        anonymous_sender=True,
        encrypted_to=["did:example:bob#key-p256-1", "did:example:bob#key-p256-2"],
        enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW,
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_pack_encrypted_for_authcrypt():
    alice_secret = Secret(
        kid="did:example:alice#key-x25519-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                    "crv": "X25519",
                    "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                }
            ),
        ),
    )

    alice_secrets_resolver = TestSecretsResolver([alice_secret])

    bob_secret_1 = Secret(
        kid="did:example:bob#key-x25519-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                    "crv": "X25519",
                    "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                }
            ),
        ),
    )

    bob_secret_2 = Secret(
        kid="did:example:bob#key-x25519-2",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                    "crv": "X25519",
                    "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                }
            ),
        ),
    )

    bob_secrets_resolver = TestSecretsResolver([bob_secret_1, bob_secret_2])

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=["did:example:alice#key-x25519-1"],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:alice#key-x25519-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:alice",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                        }
                    ),
                ),
            )
        ],
        didcomm_services=[],
    )

    bob_did_doc = TestDIDDoc(
        did="did:example:bob",
        key_agreement_kids=[
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
        ],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:bob#key-x25519-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                        }
                    ),
                ),
            ),
            VerificationMethod(
                id="did:example:bob#key-x25519-2",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                        }
                    ),
                ),
            ),
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc, bob_did_doc]))

    register_default_secrets_resolver(alice_secrets_resolver)

    message = Message(
        id="1234567890",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    pack_result = await pack_encrypted(
        message,
        to="did:example:bob",
        frm="did:example:alice",
        pack_config=PackEncryptedConfig(
            enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW, forward=False
        ),
    )

    assert pack_result.to_kids == [
        "did:example:bob#key-x25519-1",
        "did:example:bob#key-x25519-2",
    ]
    assert pack_result.from_kid == "did:example:alice#key-x25519-1"
    assert pack_result.sign_from_kid is None

    register_default_secrets_resolver(bob_secrets_resolver)

    unpack_result = await unpack(pack_result.packed_msg)

    assert unpack_result.message == message

    expected_metadata = Metadata(
        encrypted=True,
        authenticated=True,
        non_repudiation=False,
        anonymous_sender=False,
        encrypted_from="did:example:alice#key-x25519-1",
        encrypted_to=["did:example:bob#key-x25519-1", "did:example:bob#key-x25519-2"],
        enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
    )

    assert unpack_result.metadata == expected_metadata


@pytest.mark.asyncio
async def test_unpack_encrypted_for_authcrypt():
    bob_secret_1 = Secret(
        kid="did:example:bob#key-x25519-1",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                    "crv": "X25519",
                    "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                }
            ),
        ),
    )

    bob_secret_2 = Secret(
        kid="did:example:bob#key-x25519-2",
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=json_dumps(
                {
                    "kty": "OKP",
                    "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                    "crv": "X25519",
                    "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                }
            ),
        ),
    )

    register_default_secrets_resolver(TestSecretsResolver([bob_secret_1, bob_secret_2]))

    alice_did_doc = TestDIDDoc(
        did="did:example:alice",
        key_agreement_kids=["did:example:alice#key-x25519-1"],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:alice#key-x25519-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:alice",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                        }
                    ),
                ),
            )
        ],
        didcomm_services=[],
    )

    bob_did_doc = TestDIDDoc(
        did="did:example:bob",
        key_agreement_kids=[
            "did:example:bob#key-x25519-1",
            "did:example:bob#key-x25519-2",
        ],
        authentication_kids=[],
        verification_methods=[
            VerificationMethod(
                id="did:example:bob#key-x25519-1",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                        }
                    ),
                ),
            ),
            VerificationMethod(
                id="did:example:bob#key-x25519-2",
                type=VerificationMethodType.JSON_WEB_KEY_2020,
                controller="did:example:bob",
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value=json_dumps(
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                        }
                    ),
                ),
            ),
        ],
        didcomm_services=[],
    )

    register_default_did_resolver(TestDIDResolver([alice_did_doc, bob_did_doc]))

    packed_message = json_dumps(
        {
            "ciphertext": "MJezmxJ8DzUB01rMjiW6JViSaUhsZBhMvYtezkhmwts1qXWtDB63i4-FHZP6cJSyCI7eU-gqH8lBXO_U"
            "VuviWIqnIUrTRLaumanZ4q1dNKAnxNL-dHmb3coOqSvy3ZZn6W17lsVudjw7hUUpMbeMbQ5W8GokK9ZC"
            "GaaWnqAzd1ZcuGXDuemWeA8BerQsfQw_IQm-aUKancldedHSGrOjVWgozVL97MH966j3i9CJc3k9jS9x"
            "DuE0owoWVZa7SxTmhl1PDetmzLnYIIIt-peJtNYGdpd-FcYxIFycQNRUoFEr77h4GBTLbC-vqbQHJC1v"
            "W4O2LEKhnhOAVlGyDYkNbA4DSL-LMwKxenQXRARsKSIMn7z-ZIqTE-VCNj9vbtgR",
            "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6IkdGY01vcEpsamY0cExaZmNoNGFf"
            "R2hUTV9ZQWY2aU5JMWRXREd5VkNhdzAifSwiYXB2IjoiTmNzdUFuclJmUEs2OUEtcmtaMEw5WFdVRzRq"
            "TXZOQzNaZzc0QlB6NTNQQSIsInNraWQiOiJkaWQ6ZXhhbXBsZTphbGljZSNrZXkteDI1NTE5LTEiLCJh"
            "cHUiOiJaR2xrT21WNFlXMXdiR1U2WVd4cFkyVWphMlY1TFhneU5UVXhPUzB4IiwidHlwIjoiYXBwbGlj"
            "YXRpb24vZGlkY29tbS1lbmNyeXB0ZWQranNvbiIsImVuYyI6IkEyNTZDQkMtSFM1MTIiLCJhbGciOiJF"
            "Q0RILTFQVStBMjU2S1cifQ",
            "recipients": [
                {
                    "encrypted_key": "o0FJASHkQKhnFo_rTMHTI9qTm_m2mkJp-wv96mKyT5TP7QjB"
                    "DuiQ0AMKaPI_RLLB7jpyE-Q80Mwos7CvwbMJDhIEBnk2qHVB",
                    "header": {"kid": "did:example:bob#key-x25519-1"},
                },
                {
                    "encrypted_key": "rYlafW0XkNd8kaXCqVbtGJ9GhwBC3lZ9AihHK4B6J6V2kT7v"
                    "jbSYuIpr1IlAjvxYQOw08yqEJNIwrPpB0ouDzKqk98FVN7rK",
                    "header": {"kid": "did:example:bob#key-x25519-2"},
                },
            ],
            "tag": "uYeo7IsZjN7AnvBjUZE5lNryNENbf6_zew_VC-d4b3U",
            "iv": "o02OXDQ6_-sKz2PX_6oyJg",
        }
    )

    unpack_result = await unpack(packed_message)

    expected_message = Message(
        id="1234567890",
        typ="application/didcomm-plain+json",
        type="http://example.com/protocols/lets_do_lunch/1.0/proposal",
        frm="did:example:alice",
        to=["did:example:bob"],
        created_time=1516269022,
        expires_time=1516385931,
        body={"messagespecificattribute": "and its value"},
    )

    assert unpack_result.message == expected_message

    expected_metadata = Metadata(
        encrypted=True,
        authenticated=True,
        non_repudiation=False,
        anonymous_sender=False,
        encrypted_from="did:example:alice#key-x25519-1",
        encrypted_to=["did:example:bob#key-x25519-1", "did:example:bob#key-x25519-2"],
        enc_alg_auth=AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW,
    )

    assert unpack_result.metadata == expected_metadata


def _decode_and_remove_signatures(jws: str) -> dict:
    jws = json_loads(jws)
    jws["payload"] = parse_base64url_encoded_json(jws["payload"])
    for s in jws["signatures"]:
        s["protected"] = parse_base64url_encoded_json(s["protected"])
        del s["signature"]
    return jws
