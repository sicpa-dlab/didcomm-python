from dataclasses import dataclass
from typing import List, Optional, Callable

from authlib.jose.rfc7517 import AsymmetricKey

from didcomm.common.algorithms import SignAlg, AnonCryptAlg, AuthCryptAlg
from didcomm.common.types import DID_URL, DID_OR_DID_URL

DIDCOMM_ORG_DOMAIN = "didcomm.org"


class JWMFields:
    # https://datatracker.ietf.org/doc/html/draft-looker-jwm-01#page-10
    ID = "id"
    TYPE = "type"
    BODY = "body"
    TO = "to"
    FROM = "from"
    THREAD_ID = "thread_id"
    CREATED_TIME = "created_time"
    EXPIRES_TIME = "expires_time"
    REPLY_URL = "reply_url"
    REPLY_TO = "reply_to"


class DIDCommFields:
    # https://identity.foundation/didcomm-messaging/spec/#message-headers
    ID = JWMFields.ID
    TYPE = JWMFields.TYPE
    TYP = "typ"
    TO = JWMFields.TO
    FROM = JWMFields.FROM
    BODY = JWMFields.BODY
    THID = "thid"
    PTHID = "pthid"
    CREATED_TIME = "created_time"
    EXPIRES_TIME = "expires_time"
    # https://identity.foundation/didcomm-messaging/spec/#did-rotation
    FROM_PRIOR = "from_prior"
    # https://identity.foundation/didcomm-messaging/spec/#acks
    PLEASE_ACK = "please_ack"
    ACK = "ack"
    # https://identity.foundation/didcomm-messaging/spec/#messages
    NEXT = "next"
    # https://identity.foundation/didcomm-messaging/spec/#reference-2
    ATTACHMENTS = "attachments"


@dataclass(frozen=True)
class Key:
    kid: DID_URL
    key: AsymmetricKey


@dataclass(frozen=True)
class SignResult:
    msg: dict
    sign_frm_kid: DID_URL


@dataclass(frozen=True)
class EncryptResult:
    msg: dict
    to_kids: List[DID_OR_DID_URL]
    to_keys: List[Key]
    from_kid: Optional[DID_OR_DID_URL] = None


@dataclass(frozen=True)
class UnpackSignResult:
    msg: bytes
    sign_frm_kid: DID_URL
    alg: SignAlg


@dataclass(frozen=True)
class UnpackAnoncryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    alg: AnonCryptAlg


@dataclass(frozen=True)
class UnpackAuthcryptResult:
    msg: bytes
    to_kids: List[DID_URL]
    frm_kid: DID_URL
    alg: AuthCryptAlg


DIDCommGeneratorType = Callable[[Optional[DID_OR_DID_URL]], str]
