from __future__ import annotations

from typing import List, Optional

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.algorithms import AnonCryptAlg, AuthCryptAlg
from didcomm.types.message import Message
from didcomm.types.types import JSON, DID, DID_OR_KID


class Packer:

    def __init__(self, secrets_resolver: SecretsResolver = None, did_resolver: DIDResolver = None):
        pass

    async def sign(self, msg: Message, frm: DID_OR_KID = None) -> JSON:
        return ""

    async def anon_crypt(self, msg: Message, enc_alg: AnonCryptAlg,
                         to_dids: List[DID] = None) -> JSON:
        return ""

    async def auth_crypt(self, msg: Message,
                         frm: DID_OR_KID = None, to_dids: List[DID] = None,
                         enc_alg: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> JSON:
        return ""

    async def anon_auth_crypt(self, msg: Message, enc_alg_anon: AnonCryptAlg,
                              frm: DID_OR_KID = None, to_dids: List[DID] = None,
                              enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> JSON:
        return ""

    async def anon_crypt_signed(self, msg: Message, enc_alg: AnonCryptAlg,
                                frm: DID_OR_KID = None, to_dids: List[DID] = None) -> JSON:
        return ""

    async def auth_crypt_signed(self, msg: Message,
                                frm: DID_OR_KID = None, to_dids: List[DID] = None,
                                frm_sign: Optional[DID_OR_KID] = None,
                                enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> JSON:
        return ""

    async def anon_auth_crypt_signed(self, msg: Message, enc_alg_anon: AnonCryptAlg,
                                     frm: DID_OR_KID = None, to_dids: List[DID] = None,
                                     frm_sign: Optional[DID_OR_KID] = None,
                                     enc_alg_auth: AuthCryptAlg = AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW) -> JSON:
        return ""
