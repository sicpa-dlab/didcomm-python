from authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.secrets.secrets_resolver import Secret
from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory

CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519 = Secret(
    kid="did:example:charlie#key-x25519-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "d": "Z-BsgFe-eCvhuZlCBX5BV2XiDE2M92gkaORCe68YdZI",
                "crv": "X25519",
                "x": "nTiVFj7DChMsETDdxd5dIzLAJbSQ4j4UG6ZU1ogLNlw",
            }
        ),
    ),
)

CHARLIE_SECRET_AUTH_KEY_ED25519 = Secret(
    kid="did:example:charlie#key-1",
    type=VerificationMethodType.JSON_WEB_KEY_2020,
    verification_material=VerificationMaterial(
        format=VerificationMaterialFormat.JWK,
        value=json_dumps(
            {
                "kty": "OKP",
                "d": "T2azVap7CYD_kB8ilbnFYqwwYb5N-GcD6yjGEvquZXg",
                "crv": "Ed25519",
                "x": "VDXDwuGKVq91zxU6q7__jLDUq8_C5cuxECgd-1feFTE",
            }
        ),
    ),
)


class MockSecretsResolverCharlie(MockSecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
                CHARLIE_SECRET_AUTH_KEY_ED25519,
            ]
        )
