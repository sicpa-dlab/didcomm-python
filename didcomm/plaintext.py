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
        """Gets the signed JWT with this FromPrior information.
        :param secrets_resolver: the secrets resolver to use for signing the JWT
        :param iss_kid: the specific key ID of the issuer to sign the JWT
        :returns: the JWS being the signed JWT with this FromPrior information
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
    attachments: Optional[List[Attachment]] = None
    custom_headers: Optional[List[Header]] = None
    from_prior: Optional[JWT] = None


@dataclass(frozen=True)
class PlaintextBody:
    body: JSON_DATA


@dataclass(frozen=True)
class Plaintext(PlaintextHeaders, PlaintextBody):

    def to_json(self) -> JSON:
        return ""
