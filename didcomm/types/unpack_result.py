from typing import Optional, List, NamedTuple

from didcomm.types.message import Message
from didcomm.types.types import JWS, DID


class Metadata:
    frm: Optional[DID]
    to: List[DID]


class UnpackResult(NamedTuple):
    msg: Message
    metadata: Metadata
    signed_payload: Optional[JWS] = None
