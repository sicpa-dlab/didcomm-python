from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Optional, List, Union, Dict, TypeVar, Generic, Callable

import attr

from didcomm.common.types import (
    JSON_VALUE,
    DID,
    JSON_OBJ,
    JSON,
    DIDCommMessageTypes,
)
from didcomm.core.converters import converter__id, converter__didcomm_id
from didcomm.core.serialization import json_str_to_dict, json_bytes_to_dict
from didcomm.core.utils import dataclass_to_dict, attrs_to_dict, is_did
from didcomm.core.validators import (
    validator__instance_of,
    validator__deep_iterable,
    validator__optional,
    validator__deep_mapping,
    validator__not_in_,
    validator__and_,
)
from didcomm.errors import (
    MalformedMessageError,
    MalformedMessageCode,
    DIDCommValueError,
)

HeaderKeyType = str
HeaderValueType = JSON_VALUE
Header = Dict[HeaderKeyType, HeaderValueType]
T = TypeVar("T")
MESSAGE_DEFAULT_FIELDS = {
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


@attr.s(auto_attribs=True)
class Attachment:
    """Plaintext attachment"""

    data: Union[AttachmentDataLinks, AttachmentDataBase64, AttachmentDataJson]
    id: Optional[Union[str, Callable]] = attr.ib(
        converter=converter__id, validator=validator__instance_of(str), default=None
    )
    description: Optional[str] = None
    filename: Optional[str] = None
    media_type: Optional[str] = None
    format: Optional[str] = None
    lastmod_time: Optional[int] = None
    byte_count: Optional[int] = None

    def as_dict(self) -> dict:
        self._validate()
        d = attrs_to_dict(self)
        d["data"] = self.data.as_dict()
        return d

    @staticmethod
    def from_dict(d: dict) -> Attachment:
        if not isinstance(d, Dict):
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        if "data" in d:
            if not isinstance(d["data"], Dict):
                raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
            if "links" in d["data"]:
                d["data"] = AttachmentDataLinks.from_dict(d["data"])
            elif "base64" in d["data"]:
                d["data"] = AttachmentDataBase64.from_dict(d["data"])
            elif "json" in d["data"]:
                d["data"] = AttachmentDataJson.from_dict(d["data"])

        try:
            msg = Attachment(**d)
            msg._validate()
        except Exception:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        return msg

    def _validate(self):
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
            raise DIDCommValueError(f"Attachment structure is invalid: {self}")


@dataclass
class AttachmentDataLinks:
    links: List[str]
    hash: str
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        self._validate()
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataLinks:
        try:
            msg = AttachmentDataLinks(**d)
            msg._validate()
        except Exception:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        return msg

    def _validate(self):
        if (
            not isinstance(self.links, List)
            or not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError(f"AttachmentDataLinks structure is invalid: {self}")
        for link in self.links:
            if not isinstance(link, str):
                raise DIDCommValueError(f"Attachment data link is invalid: {link}")


@dataclass
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        self._validate()
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataBase64:
        try:
            msg = AttachmentDataBase64(**d)
            msg._validate()
        except Exception:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        return msg

    def _validate(self):
        if (
            not isinstance(self.base64, str)
            or self.hash
            and not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError(
                f"AttachmentDataBase64 structure is invalid: {self}"
            )


@dataclass
class AttachmentDataJson:
    json: JSON_VALUE
    hash: Optional[str] = None
    jws: Optional[JSON_OBJ] = None

    def as_dict(self) -> dict:
        self._validate()
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> AttachmentDataJson:
        try:
            msg = AttachmentDataJson(**d)
            msg._validate()
        except Exception:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        return msg

    def _validate(self):
        if (
            not isinstance(self.json, (str, int, bool, float, Dict, List))
            or self.hash
            and not isinstance(self.hash, str)
            or self.jws is not None
            and not isinstance(self.jws, Dict)
        ):
            raise DIDCommValueError(f"AttachmentDataJson structure is invalid: {self}")


@dataclass(frozen=True)
class FromPrior:
    iss: DID
    sub: DID
    aud: Optional[str] = None
    exp: Optional[int] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    jti: Optional[str] = None

    def as_dict(self) -> dict:
        self._validate()
        return dataclass_to_dict(self)

    @staticmethod
    def from_dict(d: dict) -> FromPrior:
        try:
            msg = FromPrior(**d)
            msg._validate()
        except Exception:
            raise MalformedMessageError(
                MalformedMessageCode.INVALID_PLAINTEXT,
                "from_prior plaintext is invalid",
            )

        return msg

    def _validate(self):
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
        ):
            raise DIDCommValueError(f"FromPrior structure is invalid: {self}")


@attr.s(auto_attribs=True)
class GenericMessage(Generic[T]):
    """
    Message consisting of headers and application/protocol specific data (body).
    If no `id` is specified, a UUID will be generated.
    If no `thid` is specified, it defaults to the `id` value.
    In order to convert a message to a DIDComm message for further transporting, call one of the following:
    - `pack_encrypted` to build an Encrypted DIDComm message
    - `pack_signed` to build a signed DIDComm message
    - `pack_plaintext` to build a Plaintext DIDComm message
    """

    type: str = attr.ib(validator=validator__instance_of(str))
    body: T
    # if not specified would be auto-generated
    id: Optional[Union[str, Callable]] = attr.ib(
        converter=converter__didcomm_id,
        validator=validator__optional(validator__instance_of(Union[str, Callable])),
        default=None,
    )
    frm: Optional[DID] = attr.ib(
        validator=validator__optional(validator__instance_of(DID)),
        default=None,
    )
    to: Optional[List[DID]] = attr.ib(
        validator=validator__optional(
            validator__deep_iterable(
                validator__instance_of(DID),
                iterable_validator=validator__instance_of(List),
            )
        ),
        default=None,
    )
    created_time: Optional[int] = attr.ib(
        validator=validator__optional(validator__instance_of(int)), default=None
    )
    expires_time: Optional[int] = attr.ib(
        validator=validator__optional(validator__instance_of(int)), default=None
    )
    from_prior: Optional[FromPrior] = attr.ib(
        validator=validator__optional(validator__instance_of(FromPrior)), default=None
    )
    please_ack: Optional[List[str]] = attr.ib(
        validator=validator__optional(
            validator__deep_iterable(
                validator__instance_of(str),
                iterable_validator=validator__instance_of(List),
            )
        ),
        default=None,
    )
    ack: Optional[List[str]] = attr.ib(
        validator=validator__optional(
            validator__deep_iterable(
                validator__instance_of(str),
                iterable_validator=validator__instance_of(List),
            )
        ),
        default=None,
    )
    thid: Optional[str] = attr.ib(
        validator=validator__optional(validator__instance_of(str)), default=None
    )
    pthid: Optional[str] = attr.ib(
        validator=validator__optional(validator__instance_of(str)), default=None
    )
    attachments: Optional[List[Attachment]] = attr.ib(
        validator=validator__optional(
            validator__deep_iterable(
                validator__instance_of(Attachment),
                iterable_validator=validator__instance_of(List),
            )
        ),
        default=None,
    )
    custom_headers: Optional[List[Header]] = attr.ib(
        validator=validator__optional(
            validator__deep_iterable(
                validator__deep_mapping(
                    key_validator=validator__and_(
                        validator__instance_of(HeaderKeyType),
                        validator__not_in_(MESSAGE_DEFAULT_FIELDS),
                    ),
                    value_validator=validator__instance_of(HeaderValueType),
                    mapping_validator=validator__instance_of(Dict),
                ),
                iterable_validator=validator__instance_of(List),
            )
        ),
        default=None,
    )

    def __attrs_post_init__(self):
        # If not present, the thid defaults to id (see https://identity.foundation/didcomm-messaging/spec/#threads-2)
        if self.thid is None:
            self.thid = self.id

    def _body_as_dict(self):
        if dataclasses.is_dataclass(self.body):
            return dataclass_to_dict(self.body)
        elif attr.has(type(self.body)):
            return attrs_to_dict(self.body)
        else:
            return self.body

    def as_dict(self) -> dict:
        d = attrs_to_dict(self)

        d["body"] = self._body_as_dict()

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
    def _body_from_dict(body: dict) -> T:
        return body

    # TODO TEST
    @classmethod
    def from_json(cls, msg: Union[JSON, bytes]) -> Message:
        return cls.from_dict(
            json_bytes_to_dict(msg) if isinstance(msg, bytes) else json_str_to_dict(msg)
        )

    @classmethod
    def from_dict(cls, d: dict) -> Message:
        # WARNING: that API shouldn't be called with a dict
        #          referenced from other places, from_json is better for that
        if not isinstance(d, Dict):
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        # TODO TEST missed fields
        for f in ("id", "type", "body", "typ"):
            if f not in d:
                raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        if d["typ"] != DIDCommMessageTypes.PLAINTEXT.value:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
        del d["typ"]

        if "from" in d:
            d["frm"] = d["from"]
            del d["from"]

        if "body" not in d:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)
        d["body"] = cls._body_from_dict(d["body"])

        # XXX do we expect undefined () from_prior ???
        if d.get("from_prior"):
            d["from_prior"] = FromPrior.from_dict(d["from_prior"])

        # XXX do we expect undefined (None) or empty attachments ???
        if d.get("attachments"):
            d["attachments"] = [Attachment.from_dict(e) for e in d["attachments"]]

        try:
            msg = cls(**d)
        except Exception:
            raise MalformedMessageError(MalformedMessageCode.INVALID_PLAINTEXT)

        return msg


class Message(GenericMessage[JSON_OBJ]):
    def as_dict(self) -> dict:
        if not isinstance(self.body, Dict):
            raise DIDCommValueError(f"Body structure is invalid: {self.body}")
        return super().as_dict()
