from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union, Dict, TypeVar, Generic

from didcomm.common.types import JSON_VALUE, DID, DID_URL, JSON_OBJ, DIDCommMessageTypes
from didcomm.core.utils import dataclass_to_dict
from didcomm.errors import MalformedMessageError, MalformedMessageCode

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
        d = dataclass_to_dict(self)

        if "frm" in d:
            d["from"] = d["frm"]
            del d["frm"]

        d["typ"] = DIDCommMessageTypes.PLAINTEXT.value

        if self.attachments:
            d["attachments"] = [a.as_dict() for a in self.attachments]
        if self.from_prior:
            d["from_prior"] = self.from_prior.as_dict()

        return d

    @staticmethod
    def from_dict(d: dict) -> Message:
        if "from" in d:
            d["frm"] = d["from"]
            del d["from"]
        del d["typ"]

        if "from_prior" in d:
            d["from_prior"] = FromPrior.from_dict(d["from_prior"])

        if "attachments" in d:
            d["attachments"] = [Attachment.from_dict(e) for e in d["attachments"]]

        msg = Message(**d)

        # TODO: consider using attrs lib and its validators
        if msg.id is None:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
        if msg.type is None:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
        if msg.body is None:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
        # TODO: more validation

        return msg


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

    def as_dict(self) -> dict:
        d = dataclass_to_dict(self)
        d["data"] = self.data.as_dict()
        return d

    @staticmethod
    def from_dict(d: dict) -> Attachment:
        # TODO: validation
        if "data" in d:
            if "links" in d["data"]:
                d["data"] = AttachmentDataLinks.from_dict(d["data"])
            elif "base64" in d["data"]:
                d["data"] = AttachmentDataBase64.from_dict(d["data"])
            elif "json" in d["data"]:
                d["data"] = AttachmentDataJson.from_dict(d["data"])
        return Attachment(**d)


@dataclass(frozen=True)
class AttachmentDataLinks:
    links: List[str]
    hash: str
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataLinks:
        # TODO: validation
        return AttachmentDataLinks(**d)


@dataclass(frozen=True)
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataBase64:
        # TODO: validation
        return AttachmentDataBase64(**d)


@dataclass(frozen=True)
class AttachmentDataJson:
    json: JSON_VALUE
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataJson:
        # TODO: validation
        return AttachmentDataJson(**d)


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

    def as_dict(self) -> dict:
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> FromPrior:
        # TODO: validation
        return FromPrior(**d)
