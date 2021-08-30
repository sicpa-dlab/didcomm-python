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
    ECDSA_SECP_256K1_VERIFICATION_KEY_2019 = 4
    OTHER = 1000


class VerificationMaterialFormat(Enum):
    JWK = 1
    BASE58 = 2
    OTHER = 1000


@dataclass
class VerificationMaterial:
    format: VerificationMaterialFormat
    value: str
