from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Union, List

JSON_OBJ = Dict[str, Any]
JSON_VALUE = Union[None, str, int, bool, float, JSON_OBJ, List[Any]]
JSON = str
JWK = JSON
JWT = JSON
JWS = JSON
DID = str
DID_URL = str
DID_OR_DID_URL = Union[DID, DID_URL]


class VerificationMethodType(Enum):
    JSON_WEB_KEY_2020 = 1
    X25519_KEY_AGREEMENT_KEY_2019 = 2
    ED25519_VERIFICATION_KEY_2018 = 3
    X25519_KEY_AGREEMENT_KEY_2020 = 4
    ED25519_VERIFICATION_KEY_2020 = 5
    # ECDSA_SECP_256K1_VERIFICATION_KEY_2019 = 6 - not supported now
    OTHER = 1000


class VerificationMaterialFormat(Enum):
    JWK = 1
    BASE58 = 2
    MULTIBASE = 3
    OTHER = 1000


@dataclass
class VerificationMaterial:
    format: VerificationMaterialFormat
    value: str


class DIDDocServiceTypes(Enum):
    DID_COMM_MESSAGING = "DIDCommMessaging"


class DIDCommMessageTypes(Enum):
    ENCRYPTED = "application/didcomm-encrypted+json"
    ENCRYPTED_SHORT = "didcomm-encrypted+json"
    SIGNED = "application/didcomm-signed+json"
    SIGNED_SHORT = "didcomm-signed+json"
    PLAINTEXT = "application/didcomm-plain+json"
    PLAINTEXT_SHORT = "didcomm-plain+json"


DIDCommMessageMediaTypes = DIDCommMessageTypes

# TODO
#   - replace DIDCommMessageTypes with DIDCommMessageMediaTypes
#   - rename DIDCommMessageProtocolTypes to DIDCommMessageTypes

JWT_TYPE = "JWT"


class DIDCommMessageProtocolTypes(Enum):
    FORWARD = "https://didcomm.org/routing/2.0/forward"


class JOSEFields:

    # JOSE Header fields as defined in JWS and JWE specs
    # (RFCs 7515, 7516, 7518, 7519, 7797, 8225, 8555)
    # https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-header-parameters
    JOSE_ALG = "alg"
    JOSE_JKU = "jku"
    JOSE_JWK = "jwk"
    JOSE_KID = "kid"
    JOSE_X5U = "x5u"
    JOSE_X5C = "x5c"
    JOSE_X5T = "x5t"
    JOSE_X5T_S256 = "x5t#S256"
    JOSE_TYP = "typ"
    JOSE_CTY = "cty"
    JOSE_CRIT = "crit"
    JOSE_ENC = "enc"
    JOSE_ZIP = "zip"
    JOSE_EPK = "epk"
    JOSE_APU = "apu"
    JOSE_APV = "apv"
    JOSE_IV = "iv"
    JOSE_TAG = "tag"
    JOSE_P2S = "p2s"
    JOSE_P2C = "p2c"
    JOSE_ISS = "iss"
    JOSE_SUB = "sub"
    JOSE_AUD = "aud"
    JOSE_B64 = "b64"
    JOSE_PPT = "ppt"
    JOSE_URL = "url"
    JOSE_NONCE = "nonce"

    # JWS (non-header) fields
    # https://datatracker.ietf.org/doc/html/rfc7515#section-3.2
    JWS_PROTECTED = "protected"
    JWS_HEADER = "header"
    JWS_PAYLOAD = "payload"
    JWS_SIGNATURE = "signature"

    # JWE (non-heder) fields
    # https://datatracker.ietf.org/doc/html/rfc7516#section-3.2
    JWE_PROTECTED = JWS_PROTECTED
    JWE_UNPROTECTED = "unprotected"
    JWE_HEADER = JWS_HEADER
    JWE_ENCRYPTED_KEY = "encrypted_key"
    JWE_IV = JOSE_IV
    JWE_CIPHERTEXT = "ciphertext"
    JWE_TAG = JOSE_TAG
    JWE_AAD = "aad"
