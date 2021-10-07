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
MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_X25519_1 = Secret(
    kid="did:example:mediator1#key-x25519-1",
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

MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P256_1 = Secret(
    kid="did:example:mediator1#key-p256-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
                "crv": "P-256",
                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
            }
        ),
    ),
)

MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P384_1 = Secret(
    kid="did:example:mediator1#key-p384-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
                "crv": "P-384",
                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
            }
        ),
    ),
)

MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P521_1 = Secret(
    kid="did:example:mediator1#key-p521-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "EC",
                "d": "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
                "crv": "P-521",
                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
            }
        ),
    ),
)


class MockSecretsResolverMediator1(MockSecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_X25519_1,
                MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P256_1,
                MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P384_1,
                MEDIATOR1_SECRET_KEY_AGREEMENT_KEY_P521_1,
            ]
        )
