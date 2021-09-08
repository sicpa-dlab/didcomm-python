from dataclasses import dataclass
from typing import List, Optional

from authlib.jose.rfc7517 import AsymmetricKey

from didcomm.common.algorithms import SignAlg, AnonCryptAlg, AuthCryptAlg
from didcomm.common.types import DID_URL, DID_OR_DID_URL


@dataclass(frozen=True)
class Key:
    kid: DID_URL
    key: AsymmetricKey


@dataclass(frozen=True)
class SignResult:
    msg: dict
    sign_frm_kid: DID_URL


@dataclass(frozen=True)
class EncryptResult:
    msg: dict
    to_kids: List[DID_OR_DID_URL]
    to_keys: List[Key]
    from_kid: Optional[DID_OR_DID_URL] = None


@dataclass(frozen=True)
class UnpackSignResult:
    msg: bytes
    sign_frm_kid: DID_URL
    alg: SignAlg


@dataclass(frozen=True)
class UnpackAnoncryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    alg: AnonCryptAlg


@dataclass(frozen=True)
class UnpackAuthcryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    frm_kid: DID_URL
    alg: AuthCryptAlg
