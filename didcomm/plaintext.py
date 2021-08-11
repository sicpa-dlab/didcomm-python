from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union, Dict

from didcomm.common.types import JSON_DATA, DID, DID_URL

Header = Dict[str, Union[str, int, JSON_DATA]]
SignedPlaintext = JSON_DATA


@dataclass
class PlaintextOptionalHeaders:
    """Optional headers for any Plaintext message"""
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
class PlaintextRequiredHeaders:
    """Required headers for any Plaintext message"""
    id: str
    type: str
    typ: str = "application/didcomm-plain+json"


@dataclass
class PlaintextBody:
    """Plaintext body as a application/protocol specific data"""
    body: JSON_DATA


@dataclass
class Plaintext(PlaintextOptionalHeaders, PlaintextRequiredHeaders, PlaintextBody):
    """Plaintext message consisting of headers and application/protocol specific data (body)"""
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
    jws: Optional[JSON_DATA] = None


@dataclass(frozen=True)
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JSON_DATA] = None


@dataclass(frozen=True)
class AttachmentDataJson:
    json: JSON_DATA
    hash: Optional[str] = None
    jws: Optional[JSON_DATA] = None


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
