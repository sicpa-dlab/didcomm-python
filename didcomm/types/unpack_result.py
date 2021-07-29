from enum import Enum, auto
from typing import Optional, List, NamedTuple

from didcomm.types.message import Message
from didcomm.types.types import JWS, DID, DID_OR_KID


class EncType(Enum):
    NO_ENC = auto()
    AUTH = auto()
    ANON = auto()
    ANON_AUTH = auto()


class Metadata(NamedTuple):
    enc_from: Optional[DID_OR_KID] = None
    enc_to: Optional[List[DID]] = None
    enc_typ: EncType = EncType.NO_ENC
    sign_from: Optional[DID_OR_KID] = None


class UnpackResult(NamedTuple):
    msg: Message
    metadata: Metadata
    signed_payload: Optional[JWS] = None
