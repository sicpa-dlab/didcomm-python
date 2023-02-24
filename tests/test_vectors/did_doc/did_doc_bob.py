from authlib.common.encoding import json_dumps

from didcomm import (
    DIDDoc,
    DIDCommService,
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
    VerificationMethod,
)
from didcomm.protocols.routing.forward import (
    PROFILE_DIDCOMM_V2,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
)

BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 = VerificationMethod(
    id="did:example:bob#key-x25519-1",
    controller="did:example:bob#key-x25519-1",
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
BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2 = VerificationMethod(
    id="did:example:bob#key-x25519-2",
    controller="did:example:bob#key-x25519-2",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
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
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3 = VerificationMethod(
    id="did:example:bob#key-x25519-3",
    controller="did:example:bob#key-x25519-3",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1 = VerificationMethod(
    id="did:example:bob#key-x25519-not-secrets-1",
    controller="did:example:bob#key-x25519-not-secrets-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "crv": "X25519",
                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1 = VerificationMethod(
    id="did:example:bob#key-p256-1",
    controller="did:example:bob#key-p256-1",
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
BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2 = VerificationMethod(
    id="did:example:bob#key-p256-2",
    controller="did:example:bob#key-p256-2",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1 = VerificationMethod(
    id="did:example:bob#key-p256-not-secrets-1",
    controller="did:example:bob#key-p256-not-secrets-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1 = VerificationMethod(
    id="did:example:bob#key-p384-1",
    controller="did:example:bob#key-p384-1",
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
BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2 = VerificationMethod(
    id="did:example:bob#key-p384-2",
    controller="did:example:bob#key-p384-2",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1 = VerificationMethod(
    id="did:example:bob#key-p384-not-secrets-1",
    controller="did:example:bob#key-p384-not-secrets-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1 = VerificationMethod(
    id="did:example:bob#key-p521-1",
    controller="did:example:bob#key-p521-1",
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
BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2 = VerificationMethod(
    id="did:example:bob#key-p521-2",
    controller="did:example:bob#key-p521-2",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
            }
        ),
    ),
)
BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1 = VerificationMethod(
    id="did:example:bob#key-p521-not-secrets-1",
    controller="did:example:bob#key-p521-not-secrets-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "crv": "P-521",
                "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
            }
        ),
    ),
)

DID_DOC_BOB_SPEC_TEST_VECTORS = DIDDoc(
    did="did:example:bob",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:bob#key-x25519-1",
        "did:example:bob#key-x25519-2",
        "did:example:bob#key-x25519-3",
        "did:example:bob#key-p256-1",
        "did:example:bob#key-p256-2",
        "did:example:bob#key-p384-1",
        "did:example:bob#key-p384-2",
        "did:example:bob#key-p521-1",
        "did:example:bob#key-p521-2",
    ],
    didcomm_services=[],
    verification_methods=[
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
    ],
)

DID_DOC_BOB_WITH_NO_SECRETS = DIDDoc(
    did="did:example:bob",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:bob#key-x25519-1",
        "did:example:bob#key-x25519-2",
        "did:example:bob#key-x25519-3",
        "did:example:bob#key-x25519-not-secrets-1",
        "did:example:bob#key-p256-1",
        "did:example:bob#key-p256-2",
        "did:example:bob#key-p256-not-secrets-1",
        "did:example:bob#key-p384-1",
        "did:example:bob#key-p384-2",
        "did:example:bob#key-p384-not-secrets-1",
        "did:example:bob#key-p521-1",
        "did:example:bob#key-p521-2",
        "did:example:bob#key-p521-not-secrets-1",
    ],
    didcomm_services=[
        DIDCommService(
            id="did:example:123456789abcdefghi#didcomm-1",
            service_endpoint="http://example.com/path",
            accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587],
            routing_keys=["did:example:mediator1#key-x25519-1"],
        )
    ],
    verification_methods=[
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_NOT_IN_SECRETS_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2,
        BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_NOT_IN_SECRETS_1,
    ],
)
