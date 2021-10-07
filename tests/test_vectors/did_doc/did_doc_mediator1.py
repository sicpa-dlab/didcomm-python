from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.did_doc.did_doc import VerificationMethod, DIDDoc

# FIXME build verification material
#       (currently it's a copy-paste from Bob's ones)
MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 = VerificationMethod(
    id="did:example:mediator1#key-x25519-1",
    controller="did:example:mediator1#key-x25519-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
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
)
MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P256_1 = VerificationMethod(
    id="did:example:mediator1#key-p256-1",
    controller="did:example:mediator1#key-p256-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
            }
        ),
    ),
)
MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P384_1 = VerificationMethod(
    id="did:example:mediator1#key-p384-1",
    controller="did:example:mediator1#key-p384-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
            }
        ),
    ),
)
MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P521_1 = VerificationMethod(
    id="did:example:mediator1#key-p521-1",
    controller="did:example:mediator1#key-p521-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
            }
        ),
    ),
)

DID_DOC_MEDIATOR1_SPEC_TEST_VECTORS = DIDDoc(
    did="did:example:mediator1",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:mediator1#key-x25519-1",
        "did:example:mediator1#key-p256-1",
        "did:example:mediator1#key-p384-1",
        "did:example:mediator1#key-p521-1",
    ],
    didcomm_services=[],
    verification_methods=[
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ],
)

DID_DOC_MEDIATOR1 = DIDDoc(
    did="did:example:mediator1",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:mediator1#key-x25519-1",
        "did:example:mediator1#key-p256-1",
        "did:example:mediator1#key-p384-1",
        "did:example:mediator1#key-p521-1",
    ],
    didcomm_services=[],
    verification_methods=[
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR1_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ],
)
