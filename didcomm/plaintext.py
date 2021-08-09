from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, List, Union, Dict

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import JSON_DATA, DID, JSON, JWT, DID_URL

Header = Dict[str, Union[str, int, JSON_DATA]]
SignedPlaintext = JSON_DATA


@dataclass
class PlaintextOptionalHeaders:
    """Optional headers for any Plaintext message"""
    typ: str = "application/didcomm-plain+json"
    frm: Optional[DID] = None
    to: Optional[List[DID]] = None
    created_time: Optional[int] = None
    expires_time: Optional[int] = None
    from_prior: Optional[JWT] = None
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


@dataclass
class PlaintextBody:
    """Plaintext body as a application/protocol specific data"""
    body: JSON_DATA


@dataclass
class Plaintext(PlaintextOptionalHeaders, PlaintextRequiredHeaders, PlaintextBody):
    """Plaintext message consisting of headers and application/protocol specific data (body)"""

    def to_json(self) -> JSON:
        return ""


@dataclass
class SignedPlaintext:
    data: JSON_DATA

    def to_json(self) -> JSON:
        return ""


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

    def as_jwt(self,
               iss_kid: DID_URL = None,
               resolvers_config: Optional[ResolversConfig] = None) -> JWT:
        """
        Gets the signed JWT with this FromPrior information.

        :param iss_kid: an optional key ID to be used for signing the JWT.
        If not specified, then the first key for teh given `iss` DID is used which can be resolved by the secrets resolver.
        :param resolvers_config: optional resolvers that can override a default resolvers
        registered by 'register_default_secrets_resolver' and 'register_default_did_resolver'
        :returns: the JWT with this FromPrior information
        """

    pass
