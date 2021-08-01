from typing import NamedTuple, Optional, List

from didcomm.types.attachment import Attachment
from didcomm.types.types import Body, DID, JSON, JWS


class Plaintext(NamedTuple):
    """Plaintext DIDComm message."""
    id: str
    type: str
    typ: Optional[str] = None
    frm: Optional[DID] = None
    frm_prior: Optional[JWS] = None
    to: Optional[List[DID]] = None
    please_ack: Optional[bool] = None
    ack: Optional[List[str]] = None
    thid: Optional[str] = None
    pthid: Optional[str] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None
    body: Optional[Body] = None
    attachments: Optional[List[Attachment]] = None

    def to_json(self) -> JSON:
        """Returns this plaintext as a JSON."""
        return ""
