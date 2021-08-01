from enum import Enum, auto
from typing import Optional, List, NamedTuple

from didcomm.types.plaintext import Plaintext
from didcomm.types.types import JWS, DID, KID


class EncType(Enum):
    """Type of encryption of a DIDComm message."""
    NO_ENC = auto()
    ANON = auto()
    AUTH = auto()
    ANON_AUTH = auto()


class Metadata(NamedTuple):
    """Metadata for an unpacked DIDComm message"""
    enc_frm: Optional[KID] = None
    enc_to: Optional[List[KID]] = None
    enc_type: EncType = EncType.NO_ENC
    sign_frm: Optional[KID] = None


class UnpackResult(NamedTuple):
    """Result of DIDComm message unpack operation.

    signed_message is optional and used only when the DIDComm message is signed.
    """
    plaintext: Plaintext
    metadata: Metadata
    signed_message: Optional[JWS] = None
