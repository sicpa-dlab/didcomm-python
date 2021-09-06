from authlib.common.encoding import json_dumps

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.secrets.secrets_resolver import Secret
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory

CHARLIE_SECRET_JEY_AGREEMENT_KEY_X25519 = Secret(
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


class MockSecretsResolverCharlie(SecretsResolverInMemory):
    def __init__(self):
        super().__init__(secrets=[CHARLIE_SECRET_JEY_AGREEMENT_KEY_X25519])
