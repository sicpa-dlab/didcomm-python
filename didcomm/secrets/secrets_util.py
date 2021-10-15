import json
from typing import Dict, Tuple

from authlib.common.encoding import json_dumps
from authlib.jose import OKPKey

from didcomm.common.types import (
    VerificationMethodType,
    VerificationMaterial,
    VerificationMaterialFormat,
)
from didcomm.errors import DIDCommValueError
from didcomm.secrets.secrets_resolver import Secret


def jwk_to_secret(jwk: dict) -> Secret:
    """
    Converts a JWK dict to a new Secret instance.

    :param jwk: JWK as dict
    :return: a new Secret instance
    """
    return Secret(
        kid=jwk["kid"],
        type=VerificationMethodType.JSON_WEB_KEY_2020,
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK, value=json_dumps(jwk)
        ),
    )


def secret_to_jwk_dict(secret: Secret) -> Dict:
    """
    Converts a Secret to a JWK dict. Should be used for Secrets in JWK format only.

    :param secret: s Secret to be converted
    :return: JWK dict
    """
    # assume JWK secrets only
    if secret.verification_material.format != VerificationMaterialFormat.JWK:
        raise DIDCommValueError(
            f"Unsupported format {secret.verification_material.format}"
        )
    res = json.loads(secret.verification_material.value)
    res["kid"] = secret.kid
    return res


def generate_ed25519_keys_as_jwk_dict() -> Tuple[dict, dict]:
    """
    Generates ED25519 private and public keys as JWK dicts.
    :return: private and public keys as JWK dicts
    """
    key = OKPKey.generate_key("Ed25519", is_private=True)
    private_key_jwk_dict = key.as_dict(is_private=True)
    public_key_jwk_dict = key.as_dict()
    return private_key_jwk_dict, public_key_jwk_dict


def generate_x25519_keys_as_jwk_dict() -> Tuple[dict, dict]:
    """
    Generates X25519 private and public keys as JWK dicts.
    :return: private and public keys as JWK dicts
    """
    key = OKPKey.generate_key("X25519", is_private=True)
    private_key_jwk_dict = key.as_dict(is_private=True)
    public_key_jwk_dict = key.as_dict()
    return private_key_jwk_dict, public_key_jwk_dict
