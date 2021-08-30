from authlib.common.encoding import json_loads
from authlib.jose import ECKey, OKPKey
from authlib.jose.rfc7517 import AsymmetricKey

from didcomm.common.algorithms import SignAlg
from didcomm.common.types import VerificationMaterialFormat, VerificationMethodType
from didcomm.secrets.secrets_resolver import Secret


def extract_key(secret: Secret) -> AsymmetricKey:
    if secret.type == VerificationMethodType.JSON_WEB_KEY_2020 or \
            secret.type == VerificationMethodType.ED25519_VERIFICATION_KEY_2018:
        if secret.verification_material.format == VerificationMaterialFormat.JWK:
            jwk = json_loads(secret.verification_material.value)
            if jwk['kty'] == 'EC':
                return ECKey.import_key(jwk)
            elif jwk['kty'] == 'OKP':
                return OKPKey.import_key(jwk)
            else:
                # FIXME
                raise NotImplemented()
        else:
            # FIXME
            raise NotImplemented()
    else:
        # FIXME
        raise NotImplemented()


def extract_sign_alg(secret: Secret) -> SignAlg:
    if secret.type == VerificationMethodType.JSON_WEB_KEY_2020:
        if secret.verification_material.format == VerificationMaterialFormat.JWK:
            jwk = json_loads(secret.verification_material.value)
            if jwk['kty'] == 'EC' and jwk['crv'] == 'P-256':
                return SignAlg.ES256
            elif jwk['kty'] == 'EC' and jwk['crv'] == 'secp256k1':
                return SignAlg.ES256K
            elif jwk['kty'] == 'OKP' and jwk['crv'] == 'Ed25519':
                return SignAlg.ED25519
            else:
                # FIXME
                raise NotImplemented()
        else:
            # FIXME
            raise NotImplemented()
    elif secret.type == VerificationMethodType.ED25519_VERIFICATION_KEY_2018:
        return SignAlg.ED25519
    elif secret.type == VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019:
        return SignAlg.ES256K
    else:
        # FIXME
        raise NotImplemented()
