from typing import NamedTuple, Optional, List

from didcomm.types.types import Payload, DID, JSON


class Message(NamedTuple):
    payload: Payload
    id: str
    type: str
    typ: Optional[str] = None
    frm: Optional[DID] = None
    to: Optional[List[DID]] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None
    attachments: Optional[JSON] = None

    def to_json(self) -> JSON:
        return ""
