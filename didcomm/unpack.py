from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, List

from didcomm.common.types import DID_OR_KID, JWS, JSON
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class UnpackOpts:
    expect_signed: bool = False
    expect_encrypted: bool = False
    expect_authenticated: bool = False
    expect_sender_hidden: bool = False
    expect_signed_by_encrypter: bool = True
    expect_decrypt_by_all_keys: bool = False
    unwrap_re_wrapping_forward: bool = True


class EncType(Enum):
    NO_ENC = auto()
    AUTH = auto()
    ANON = auto()
    ANON_AUTH = auto()


@dataclass(frozen=True)
class Metadata:
    enc_from: Optional[DID_OR_KID] = None
    enc_to: Optional[List[DID_OR_KID]] = None
    enc_typ: EncType = EncType.NO_ENC
    sign_from: Optional[DID_OR_KID] = None


@dataclass(frozen=True)
class UnpackResult:
    plaintext: Plaintext
    metadata: Metadata
    signed_plaintext: Optional[JWS] = None


class Unpacker:

    def __init__(self,
                 unpack_opts: UnpackOpts = None,
                 secrets_resolver: SecretsResolver = None,
                 did_resolver: DIDResolver = None):
        pass

    async def unpack(self, msg: JSON) -> UnpackResult:
        return UnpackResult(
            plaintext=Plaintext(body={}, id="", type=""),
            metadata=Metadata(),
            signed_plaintext=None
        )
