from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union, Dict, TypeVar, Generic

from didcomm.common.types import JSON_VALUE, DID, DID_URL, JSON_OBJ, DIDCommMessageTypes
from didcomm.core.utils import dataclass_to_dict, is_did, is_did_url
from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDCommValueError,
)

Header = Dict[str, JSON_VALUE]
T = TypeVar("T")


# TODO: dataclasses require Python 3.7.
# Think about alternative approach with the same properties (attrs lib for example) that can work on Python 3.5
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

    # TODO: refactor
    __DEFAULT_FIELDS = {
        "id",
        "type",
        "body",
        "frm",
        "to",
        "created_time",
        "expires_time",
        "from_prior",
        "please_ack",
        "ack",
        "thid",
        "pthid",
        "attachments",
    }

    def as_dict(self) -> dict:
        d = dataclass_to_dict(self)

        if (
            not isinstance(self.id, str)
            or not isinstance(self.type, str)
            or self.frm is not None
            and not isinstance(self.frm, str)
            or self.to is not None
            and not isinstance(self.to, List)
            or self.created_time is not None
            and not isinstance(self.created_time, int)
            or self.expires_time is not None
            and not isinstance(self.expires_time, int)
            or self.please_ack is not None
            and not isinstance(self.please_ack, bool)
            or self.ack is not None
            and not isinstance(self.ack, str)
            or self.thid is not None
            and not isinstance(self.thid, str)
            or self.pthid is not None
            and not isinstance(self.pthid, str)
            or self.from_prior is not None
            and not isinstance(self.from_prior, FromPrior)
            or self.attachments is not None
            and not isinstance(self.attachments, List)
            or self.custom_headers is not None
            and not isinstance(self.custom_headers, List)
        ):
            raise DIDCommValueError()

        if self.to is not None:
            for to in self.to:
                if not isinstance(to, str):
                    raise DIDCommValueError()
        if self.attachments is not None:
            for attachment in self.attachments:
                if not isinstance(attachment, Attachment):
                    raise DIDCommValueError()
        if self.custom_headers is not None:
            for custom_header in self.custom_headers:
                if not isinstance(custom_header, Dict):
                    raise DIDCommValueError()
                for k in custom_header.keys():
                    if k in self.__DEFAULT_FIELDS:
                        raise DIDCommValueError()

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


class Message(GenericMessage[JSON_OBJ]):
    def as_dict(self) -> dict:
        if not isinstance(self.body, Dict):
            raise DIDCommValueError()
        return super().as_dict()


@dataclass
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
        if (
            not isinstance(self.id, str)
            or not isinstance(
                self.data,
                (AttachmentDataLinks, AttachmentDataBase64, AttachmentDataJson),
            )
            or self.description is not None
            and not isinstance(self.description, str)
            or self.filename is not None
            and not isinstance(self.filename, str)
            or self.media_type is not None
            and not isinstance(self.media_type, str)
            or self.format is not None
            and not isinstance(self.format, str)
            or self.lastmod_time is not None
            and not isinstance(self.lastmod_time, int)
            or self.byte_count is not None
            and not isinstance(self.byte_count, int)
        ):
            raise DIDCommValueError()

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


@dataclass
class AttachmentDataLinks:
    links: List[str]
    hash: str
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        if (
            not isinstance(self.links, List)
            or not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError()
        for link in self.links:
            if not isinstance(link, str):
                raise DIDCommValueError()

        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataLinks:
        # TODO: validation
        return AttachmentDataLinks(**d)


@dataclass
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        if (
            not isinstance(self.base64, str)
            or self.hash
            and not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError()

        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataBase64:
        # TODO: validation
        return AttachmentDataBase64(**d)


@dataclass
class AttachmentDataJson:
    json: JSON_VALUE
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        if (
            not isinstance(self.json, (str, int, bool, float, Dict, List))
            or self.hash
            and not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError()

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
    iss_kid: Optional[DID_URL] = None

    def as_dict(self) -> dict:
        if (
            not is_did(self.iss)
            or not is_did(self.sub)
            or not isinstance(self.sub, str)
            or self.aud is not None
            and not isinstance(self.aud, str)
            or self.exp is not None
            and not isinstance(self.exp, int)
            or self.nbf is not None
            and not isinstance(self.nbf, int)
            or self.iat is not None
            and not isinstance(self.iat, int)
            or self.jti is not None
            and not isinstance(self.jti, str)
            or self.iss_kid is not None
            and not is_did_url(self.iss_kid)
        ):
            raise DIDCommValueError()

        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> FromPrior:
        # TODO: validation
        return FromPrior(**d)
