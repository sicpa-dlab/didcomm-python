from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.did_doc.did_doc import VerificationMethod, DIDDoc, DIDCommService

# FIXME build verification material
#       (currently it's a copy-paste from Bob's ones)
from didcomm.protocols.routing.forward import (
    PROFILE_DIDCOMM_V2,
    PROFILE_DIDCOMM_AIP2_ENV_RFC587,
)

MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1 = VerificationMethod(
    id="did:example:mediator2#key-x25519-1",
    controller="did:example:mediator2#key-x25519-1",
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
MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1 = VerificationMethod(
    id="did:example:mediator2#key-p256-1",
    controller="did:example:mediator2#key-p256-1",
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
MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1 = VerificationMethod(
    id="did:example:mediator2#key-p384-1",
    controller="did:example:mediator2#key-p384-1",
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
MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1 = VerificationMethod(
    id="did:example:mediator2#key-p521-1",
    controller="did:example:mediator2#key-p521-1",
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

DID_DOC_MEDIATOR2_SPEC_TEST_VECTORS = DIDDoc(
    did="did:example:mediator2",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:mediator2#key-x25519-1",
        "did:example:mediator2#key-p256-1",
        "did:example:mediator2#key-p384-1",
        "did:example:mediator2#key-p521-1",
    ],
    didcomm_services=[],
    verification_methods=[
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ],
)

DID_DOC_MEDIATOR2 = DIDDoc(
    did="did:example:mediator2",
    authentication_kids=[],
    key_agreement_kids=[
        "did:example:mediator2#key-x25519-1",
        "did:example:mediator2#key-p256-1",
        "did:example:mediator2#key-p384-1",
        "did:example:mediator2#key-p521-1",
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
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_X25519_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P256_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P384_1,
        MEDIATOR2_VERIFICATION_METHOD_KEY_AGREEM_P521_1,
    ],
)
