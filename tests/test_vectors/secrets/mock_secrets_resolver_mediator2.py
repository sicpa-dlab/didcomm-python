from didcomm.vendor.authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.secrets.secrets_resolver import Secret
from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory

# FIXME build verification material
#       (currently it's a copy-paste from Bob's ones)
MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_X25519_1 = Secret(
    kid="did:example:mediator2#key-x25519-1",
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

MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P256_1 = Secret(
    kid="did:example:mediator2#key-p256-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
                "crv": "P-256",
                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
            }
        ),
    ),
)

MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P384_1 = Secret(
    kid="did:example:mediator2#key-p384-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
                "crv": "P-384",
                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
            }
        ),
    ),
)

MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P521_1 = Secret(
    kid="did:example:mediator2#key-p521-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "ABixMEZHsyT7SRw-lY5HxdNOofTZLlwBHwPEJ3spEMC2sWN1RZQylZuvoyOBGJnPxg4-H_iVhNWf_OtgYODrYhCk",
                "crv": "P-521",
                "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
            }
        ),
    ),
)


class MockSecretsResolverMediator2(MockSecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P256_1,
                MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P384_1,
                MEDIATOR2_SECRET_KEY_AGREEMENT_KEY_P521_1,
            ]
        )
