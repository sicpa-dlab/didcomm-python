from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union, Dict

from didcomm.common.types import JSON_VALUE, DID, DID_URL, JSON_OBJ

Header = Dict[str, JSON_VALUE]


@dataclass
class MessageOptionalHeaders:
    """Optional headers for a message"""

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


@dataclass
class MessageRequiredHeaders:
    """Required headers for a message"""

    id: str
    type: str
    typ: str = "application/didcomm-plain+json"


@dataclass
class MessageBody:
    """Message body as a application/protocol specific data"""

    body: JSON_OBJ


@dataclass
class Message(MessageOptionalHeaders, MessageRequiredHeaders, MessageBody):
    """
    Message consisting of headers and application/protocol specific data (body).
    In order to convert a message to a DIDComm message for further transporting, call one of the following:
    - `pack_encrypted` to build an Encrypted DIDComm message
    - `pack_signed` to build a signed DIDComm message
    - `pack_plaintext` to build a Plaintext DIDComm message
    """

    pass


@dataclass(frozen=True)
class Attachment:
    """Plaintext attachment"""

    id: str
    data: Union[AttachmentDataLinks, AttachmentDataBase64, AttachmentDataJson]
    description: Optional[str] = None
    filename: Optional[str] = None
    mime_type: Optional[str] = None
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
