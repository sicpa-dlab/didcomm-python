from dataclasses import dataclass
from typing import Optional, List, Union, Dict

from didcomm.common.types import JWS, JSON_DATA, DID, JSON, KID, JWT
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class AttachmentDataLinks:
    links: List[str]
    hash: str
    jws: Optional[JWS] = None


@dataclass(frozen=True)
class AttachmentDataBase64:
    base64: str
    hash: Optional[str] = None
    jws: Optional[JWS] = None


@dataclass(frozen=True)
class AttachmentDataJson:
    json: JSON_DATA
    hash: Optional[str] = None
    jws: Optional[JWS] = None


@dataclass(frozen=True)
class Attachment:
    """attachments list element of a plaintext."""
    id: str
    data: Union[AttachmentDataLinks, AttachmentDataBase64, AttachmentDataJson]
    description: Optional[str] = None
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    format: Optional[str] = None
    lastmod_time: Optional[int] = None
    byte_count: Optional[int] = None


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
               iss_kid: KID = None,
               did_resolver: Optional[DIDResolver] = None,
               secrets_resolver: Optional[SecretsResolver] = None) -> JWT:
        """
        Gets the signed JWT with this FromPrior information.

        :param iss_kid: an optional key ID to be used for signing the JWT.
        If not specified, then the first key for teh given `iss` DID is used which can be resolved by the secrets resolver.
        :param secrets_resolver: an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'
        :param did_resolver: an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'
        :returns: the JWT with this FromPrior information
        """

    pass


Header = Dict[str, Union[str, int, JSON_DATA]]


@dataclass(frozen=True)
class PlaintextHeaders:
    id: str
    type: str
    typ: Optional[str] = None
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


@dataclass(frozen=True)
class PlaintextBody:
    body: JSON_DATA


@dataclass(frozen=True)
class Plaintext(PlaintextHeaders, PlaintextBody):

    def to_json(self) -> JSON:
        return ""
