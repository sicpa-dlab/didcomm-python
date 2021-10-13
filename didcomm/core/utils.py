import dataclasses
import hashlib
import uuid
from enum import Enum
from typing import Union, Optional, Any, List

import attr
import base58
import varint
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
    method: Union[VerificationMethod, Secret], align_kid=False
) -> AsymmetricKey:
    if isinstance(method, VerificationMethod):
        return _extract_key_from_verifciation_method(method, align_kid)
    else:
        return _extract_key_from_secret(method, align_kid)


def _extract_key_from_verifciation_method(
    verification_method: VerificationMethod, align_kid
) -> AsymmetricKey:
    if verification_method.type == VerificationMethodType.JSON_WEB_KEY_2020:
        if (
            verification_method.verification_material.format
            != VerificationMaterialFormat.JWK
        ):
            raise DIDCommValueError(
                f"Verification material format {verification_method.verification_material.format} "
                f"is not supported for verification method type {verification_method.type}"
            )

        jwk = json_str_to_dict(verification_method.verification_material.value)

        if align_kid:
            jwk["kid"] = verification_method.id

        if jwk["kty"] == "EC":
            return ECKey.import_key(jwk)
        elif jwk["kty"] == "OKP":
            return OKPKey.import_key(jwk)
        else:
            raise DIDCommValueError(f"JWK key type {jwk['kty']} is not supported")

    elif verification_method.type in [
        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
        VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
    ]:
        if (
            verification_method.verification_material.format
            != VerificationMaterialFormat.BASE58
        ):
            raise DIDCommValueError(
                f"Verification material format {verification_method.verification_material.format} "
                f"is not supported for verification method type {verification_method.type}"
            )

        raw_value = base58.b58decode(verification_method.verification_material.value)
        base64url_value = urlsafe_b64encode(raw_value)

        jwk = {
            "kty": "OKP",
            "crv": "X25519"
            if verification_method.type
            == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
            else "Ed25519",
            "x": to_unicode(base64url_value),
        }

        if align_kid:
            jwk["kid"] = verification_method.id

        return OKPKey.import_key(jwk)

    elif verification_method.type in [
        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
        VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
    ]:
        if (
            verification_method.verification_material.format
            != VerificationMaterialFormat.MULTIBASE
        ):
            raise DIDCommValueError(
                f"Verification material format {verification_method.verification_material.format} "
                f"is not supported for verification method type {verification_method.type}"
            )

        # Currently only base58btc encoding is supported in scope of multibase support
        if verification_method.verification_material.value.startswith("z"):
            prefixed_raw_value = base58.b58decode(
                verification_method.verification_material.value[1:]
            )
        else:
            raise DIDCommValueError(
                f"Multibase keys containing internally Base58 values only are currently supported "
                f"but got the value: {verification_method.verification_material.value}"
            )

        codec, raw_value = _from_multicodec(prefixed_raw_value)

        expected_codec = (
            _Codec.X25519_PUB
            if verification_method.type
            == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            else _Codec.ED25519_PUB
        )

        if codec != expected_codec:
            raise DIDCommValueError(
                f"Multibase public key value contains multicodec prefix "
                f"which is inappropriate for verification method type {verification_method.type}"
            )

        base64url_value = urlsafe_b64encode(raw_value)

        jwk = {
            "kty": "OKP",
            "crv": "X25519"
            if verification_method.type
            == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            else "Ed25519",
            "x": to_unicode(base64url_value),
        }

        if align_kid:
            jwk["kid"] = verification_method.id

        return OKPKey.import_key(jwk)

    else:
        raise DIDCommValueError(
            f"Verification method type {verification_method.type} is not supported"
        )


_CURVE25519_POINT_SIZE = 32


def _extract_key_from_secret(secret: Secret, align_kid) -> AsymmetricKey:
    if secret.type == VerificationMethodType.JSON_WEB_KEY_2020:
        if secret.verification_material.format != VerificationMaterialFormat.JWK:
            raise DIDCommValueError(
                f"Verification material format {secret.verification_material.format} "
                f"is not supported for secret type {secret.type}"
            )

        jwk = json_str_to_dict(secret.verification_material.value)

        if align_kid:
            jwk["kid"] = secret.kid

        if jwk["kty"] == "EC":
            return ECKey.import_key(jwk)
        elif jwk["kty"] == "OKP":
            return OKPKey.import_key(jwk)
        else:
            raise DIDCommValueError(f"JWK key type {jwk['kty']} is not supported")

    elif secret.type in [
        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019,
        VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
    ]:
        if secret.verification_material.format != VerificationMaterialFormat.BASE58:
            raise DIDCommValueError(
                f"Verification material format {secret.verification_material.format} "
                f"is not supported for secret type {secret.type}"
            )

        raw_value = base58.b58decode(secret.verification_material.value)

        raw_d_value = raw_value[:_CURVE25519_POINT_SIZE]
        raw_x_value = raw_value[_CURVE25519_POINT_SIZE:]

        base64url_d_value = urlsafe_b64encode(raw_d_value)
        base64url_x_value = urlsafe_b64encode(raw_x_value)

        jwk = {
            "kty": "OKP",
            "crv": "X25519"
            if secret.type == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
            else "Ed25519",
            "x": to_unicode(base64url_x_value),
            "d": to_unicode(base64url_d_value),
        }

        if align_kid:
            jwk["kid"] = secret.kid

        return OKPKey.import_key(jwk)

    elif secret.type in [
        VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
        VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
    ]:
        if secret.verification_material.format != VerificationMaterialFormat.MULTIBASE:
            raise DIDCommValueError(
                f"Verification material format {secret.verification_material.format} "
                f"is not supported for secret type {secret.type}"
            )

        # Currently only base58btc encoding is supported in scope of multibase support
        if secret.verification_material.value.startswith("z"):
            prefixed_raw_value = base58.b58decode(
                secret.verification_material.value[1:]
            )
        else:
            raise DIDCommValueError(
                f"Multibase keys containing internally Base58 values only are currently supported "
                f"but got the value: {secret.verification_material.value}"
            )

        codec, raw_value = _from_multicodec(prefixed_raw_value)

        expected_codec = (
            _Codec.X25519_PRIV
            if secret.type == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            else _Codec.ED25519_PRIV
        )

        if codec != expected_codec:
            raise DIDCommValueError(
                f"Multibase private key value contains multicodec prefix "
                f"which is inappropriate for secret type {secret.type}"
            )

        raw_d_value = raw_value[:_CURVE25519_POINT_SIZE]
        raw_x_value = raw_value[_CURVE25519_POINT_SIZE:]

        base64url_d_value = urlsafe_b64encode(raw_d_value)
        base64url_x_value = urlsafe_b64encode(raw_x_value)

        jwk = {
            "kty": "OKP",
            "crv": "X25519"
            if secret.type == VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            else "Ed25519",
            "x": to_unicode(base64url_x_value),
            "d": to_unicode(base64url_d_value),
        }

        if align_kid:
            jwk["kid"] = secret.kid

        return OKPKey.import_key(jwk)

    else:
        raise DIDCommValueError(f"Secret type {secret.type} is not supported")


class _Codec(Enum):
    X25519_PUB = 0xEC
    ED25519_PUB = 0xED
    ED25519_PRIV = 0x1300
    X25519_PRIV = 0x1302


def _from_multicodec(value: bytes) -> (_Codec, bytes):
    try:
        prefix_int = varint.decode_bytes(value)
    except Exception:
        raise DIDCommValueError("Invalid multicodec prefix in {}".format(str(value)))

    try:
        codec = _Codec(prefix_int)
    except DIDCommValueError:
        raise DIDCommValueError(
            "Unknown multicodec prefix {} in {}".format(str(prefix_int), str(value))
        )

    prefix = varint.encode(prefix_int)
    return codec, value[len(prefix) :]


def extract_sign_alg(method: Union[VerificationMethod, Secret]) -> SignAlg:
    if method.type == VerificationMethodType.JSON_WEB_KEY_2020:
        if method.verification_material.format != VerificationMaterialFormat.JWK:
            raise DIDCommValueError(
                f"Verification material format {method.verification_material.format} "
                f"is not supported for verification method type {method.type}"
            )

        jwk = json_str_to_dict(method.verification_material.value)

        if jwk["kty"] == "EC" and jwk["crv"] == "P-256":
            return SignAlg.ES256
        elif jwk["kty"] == "EC" and jwk["crv"] == "secp256k1":
            return SignAlg.ES256K
        elif jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
            return SignAlg.ED25519
        else:
            raise DIDCommValueError(
                f"Keys of {jwk['kty']} type with {jwk['crv']} curve are not supported for signing/verification"
            )

    elif method.type in [
        VerificationMethodType.ED25519_VERIFICATION_KEY_2018,
        VerificationMethodType.ED25519_VERIFICATION_KEY_2020,
    ]:
        return SignAlg.ED25519

    # elif method.type == VerificationMethodType.ECDSA_SECP_256K1_VERIFICATION_KEY_2019:
    #     return SignAlg.ES256K

    else:
        raise DIDCommValueError(
            f"Verification method type {method.type} is not supported for signing/verification"
        )


# TODO TEST
def is_did(v: Any) -> bool:
    # TODO
    #   - consider other presentations (e.g bytes)
    #   - strict verifications for parts
    #     (https://www.w3.org/TR/did-core/#did-syntax)
    if isinstance(v, (str, DID)):
        parts = str(v).split(":")
        return len(parts) >= 3 and parts[0] == "did" and all(parts)
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
