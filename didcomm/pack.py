from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Dict

from didcomm.common.types import JSON, DID_OR_KID, DID
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.plaintext import Plaintext
from didcomm.secrets.secrets_resolver import SecretsResolver


class AnonCryptAlg(Enum):
    A256CBC_HS512_ECDH_ES_A256KW = auto()
    XC20P_ECDH_ES_A256KW = auto()
    A256GCM_ECDH_ES_A256KW = auto()


class AuthCryptAlg(Enum):
    A256CBC_HS512_ECDH_1PU_A256KW = auto()


@dataclass(frozen=True)
class PackedForward:
    packed_forward_msg: JSON
    service_endpoint: str


@dataclass(frozen=True)
class PackResult:
    packed_msg: JSON
    packed_forward_msgs: Dict[DID, Optional[PackedForward]]


class Packer:

    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None,
                 forward: bool = True):
        pass

    async def pack_plaintext(self, msg: Plaintext) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def sign(self, msg: Plaintext, frm: DID_OR_KID = None) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_crypt(self, msg: Plaintext, enc_alg: AnonCryptAlg,
                         to_dids: List[DID] = None) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def auth_crypt(self, msg: Plaintext,
                         frm: DID_OR_KID = None, to_dids: List[DID] = None,
                         enc_alg: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_auth_crypt(self, msg: Plaintext, enc_alg_anon: AnonCryptAlg,
                              frm: DID_OR_KID = None, to_dids: List[DID] = None,
                              enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_crypt_signed(self, msg: Plaintext, enc_alg: AnonCryptAlg,
                                frm: DID_OR_KID = None, to_dids: List[DID] = None) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def auth_crypt_signed(self, msg: Plaintext,
                                frm_enc: DID_OR_KID = None, to_dids: List[DID] = None,
                                frm_sign: Optional[DID_OR_KID] = None,
                                enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})

    async def anon_auth_crypt_signed(self, msg: Plaintext, enc_alg_anon: AnonCryptAlg,
                                     frm_enc: DID_OR_KID = None, to_dids: List[DID] = None,
                                     frm_sign: Optional[DID_OR_KID] = None,
                                     enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> PackResult:
        return PackResult(packed_msg="", packed_forward_msgs={to: PackedForward("", "") for to in msg.to})
