from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Optional, List, Union, Dict, TypeVar, Generic

from didcomm.common.types import JSON_VALUE, DID, DID_URL, JSON_OBJ, DIDCommMessageTypes

Header = Dict[str, JSON_VALUE]
T = TypeVar("T")


@dataclass
class GenericMessage(Generic[T]):
    """
    Message consisting of headers and application/protocol specific data (body).
    In order to convert a message to a DIDComm message for further transporting, call one of the following:
    - `pack_encrypted` to build an Encrypted DIDComm message
    - `pack_signed` to build a signed DIDComm message
    - `pack_plaintext` to build a Plaintext DIDComm message
    """

    id: str
    type: str
    body: T
    frm: Optional[DID] = None
    to: Optional[List[DID]] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None
    from_prior: Optional[FromPrior] = None
    please_ack: Optional[bool] = None
    ack: Optional[List[str]] = None
    thid: Optional[str] = None
    pthid: Optional[str] = None
    attachments: Optional[List[Attachment]] = None
    custom_headers: Optional[List[Header]] = None

    def as_dict(self) -> dict:
        d = dataclasses.asdict(self)
        for k in set(d.keys()):
            if d[k] is None:
                del d[k]
        if "frm" in d:
            d["from"] = d["frm"]
            del d["frm"]
        d["typ"] = DIDCommMessageTypes.PLAINTEXT.value
        return d

    @staticmethod
    def from_dict(d: dict) -> Message:
        if "from" in d:
            d["frm"] = d["from"]
            del d["from"]
        del d["typ"]
        return Message(**d)


Message = GenericMessage[JSON_OBJ]


@dataclass(frozen=True)
class Attachment:
    """Plaintext attachment"""

    id: str
    data: Union[AttachmentDataLinks, AttachmentDataBase64, AttachmentDataJson]
    description: Optional[str] = None
    filename: Optional[str] = None
    media_type: Optional[str] = None
    format: Optional[str] = None
    lastmod_time: Optional[int] = None
    byte_count: Optional[int] = None


@dataclass(frozen=True)
class AttachmentDataLinks:
    links: List[str]
    hash: str
    jws: Optional[JSON_OBJ] = None


@dataclass(frozen=True)
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None


@dataclass(frozen=True)
class AttachmentDataJson:
    json: JSON_VALUE
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None


@dataclass(frozen=True)
class FromPrior:
    iss: DID
    sub: DID
    aud: Optional[str] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None
    iss_kid: DID_URL = None
