import dataclasses
import hashlib

import attr
import uuid
from typing import Union, Optional, Any, List

from authlib.common.encoding import (
    to_unicode,
    urlsafe_b64decode,
    to_bytes,
    urlsafe_b64encode,
)
from authlib.jose import ECKey, OKPKey
from authlib.jose.rfc7517 import AsymmetricKey

from didcomm.common.algorithms import SignAlg
from didcomm.common.types import (
    VerificationMaterialFormat,
    VerificationMethodType,
    DID_OR_DID_URL,
    DID_URL,
    DID,
)
from didcomm.core.serialization import json_str_to_dict
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import DIDCommValueError
from didcomm.secrets.secrets_resolver import Secret


def id_generator_default() -> str:
    return str(uuid.uuid4())


def didcomm_id_generator_default(did: Optional[DID_OR_DID_URL] = None) -> str:
    res = id_generator_default()
    if did:
        res = f"{did}:{res}"
    return res


def extract_key(
    verification_method: Union[VerificationMethod, Secret], align_kid=False
) -> AsymmetricKey:
    if (
        verification_method.type == VerificationMethodType.JSON_WEB_KEY_2020
        and verification_method.verification_material.format
        == VerificationMaterialFormat.JWK
    ):
        jwk = json_str_to_dict(verification_method.verification_material.value)

        if align_kid:
            if isinstance(verification_method, VerificationMethod):
                kid = verification_method.id
            else:
                kid = verification_method.kid
            jwk["kid"] = kid

        if jwk["kty"] == "EC":
            return ECKey.import_key(jwk)
        elif jwk["kty"] == "OKP":
            return OKPKey.import_key(jwk)

        raise DIDCommValueError()

    # elif verification_method.type == (
    #     VerificationMethodType.ED25519_VERIFICATION_KEY_2018
    # ):
    #     # FIXME
    #     raise NotImplementedError()

    raise DIDCommValueError()


def extract_sign_alg(verification_method: Union[VerificationMethod, Secret]) -> SignAlg:
    if (
        verification_method.type == VerificationMethodType.JSON_WEB_KEY_2020
        and verification_method.verification_material.format
        == VerificationMaterialFormat.JWK
    ):
        jwk = json_str_to_dict(verification_method.verification_material.value)
        if jwk["kty"] == "EC" and jwk["crv"] == "P-256":
            return SignAlg.ES256
        elif jwk["kty"] == "EC" and jwk["crv"] == "secp256k1":
            return SignAlg.ES256K
        elif jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
            return SignAlg.ED25519

        raise DIDCommValueError()

    # elif verification_method.type == (
    #     VerificationMethodType.ED25519_VERIFICATION_KEY_2018
    # ):
    #     return SignAlg.ED25519
    #
    # elif (
    #     verification_method.type
    #     == VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019
    # ):
    #     return SignAlg.ES256K

    raise DIDCommValueError()


# TODO TEST
def is_did(v: Any) -> bool:
    # TODO
    #   - consider other presentations (e.g bytes)
    #   - strict verifications for parts
    #     (https://www.w3.org/TR/did-core/#did-syntax)
    if isinstance(v, (str, DID)):
        parts = str(v).split(":")
        return len(parts) == 3 and parts[0] == "did" and all(parts)
    return False


# TODO TEST
def is_did_url(v: Any) -> bool:
    # TODO
    #   - consider other presentations (e.g bytes)
    #   - verifications for after-did parts
    #     (https://www.w3.org/TR/did-core/#did-url-syntax)
    if isinstance(v, (str, DID_URL)):
        before, sep, after = str(v).partition("#")  # always 3-tuple
        return sep and after and is_did(before)
    return False


# TODO TEST
def is_did_or_did_url(v: Any) -> bool:
    return is_did(v) or is_did_url(v)


def get_did(did_or_did_url: DID_OR_DID_URL) -> DID:
    return did_or_did_url.partition("#")[0]


def get_did_and_optionally_kid(did_or_kid: DID_OR_DID_URL) -> (DID, Optional[DID_URL]):
    if is_did_url(did_or_kid):
        did = get_did(did_or_kid)
        kid = did_or_kid
    else:
        did = did_or_kid
        kid = None
    return did, kid


def are_keys_compatible(
    method1: Union[Secret, VerificationMethod], method2: VerificationMethod
) -> bool:
    if method1.type == method2.type and (
        method1.verification_material.format == method2.verification_material.format
    ):
        if method1.verification_material.format == VerificationMaterialFormat.JWK:
            private_jwk = json_str_to_dict(method1.verification_material.value)
            public_jwk = json_str_to_dict(method2.verification_material.value)
            return (
                private_jwk["kty"] == public_jwk["kty"]
                and private_jwk["crv"] == public_jwk["crv"]
            )
        else:
            return True
    else:
        return False


def parse_base64url_encoded_json(base64url):
    return json_str_to_dict(to_unicode(urlsafe_b64decode(to_bytes(base64url))))


def get_jwe_alg(jwe: dict) -> Optional[str]:
    if "protected" not in jwe:
        return None

    try:
        protected = parse_base64url_encoded_json(jwe["protected"])
    except Exception:
        return None

    return protected.get("alg")


def dict_cleanup(d: dict) -> dict:
    for k in set(d.keys()):
        if d[k] is None:
            del d[k]
    return d


def dataclass_to_dict(msg) -> dict:
    return dict_cleanup(dataclasses.asdict(msg))


def attrs_to_dict(attrs_inst: Any) -> dict:
    return dict_cleanup(attr.asdict(attrs_inst))


def calculate_apv(kids: List[DID_URL]) -> str:
    return to_unicode(
        urlsafe_b64encode(hashlib.sha256(to_bytes(".".join(sorted(kids)))).digest())
    )
