from __future__ import annotations

from typing import List

from didcomm.algorithms import KWAlgAuthCrypt, EncAlgAnonCrypt, KWAlgAnonCrypt, EncAlgAuthCrypt
from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types import Payload, JSON, DID, KID


class MessageBuilder:

    def __init__(self, payload: Payload, id: str, type: str) -> None:
        self.__payload = payload
        self.__id = id
        self.__type = type

    def build(self) -> JSON:
        pass

    def typ(self, typ: str) -> MessageBuilder:
        return self

    def frm(self, frm: DID) -> MessageBuilder:
        return self

    def to(self, to: List[DID]) -> MessageBuilder:
        return self

    def created_time(self, created_time: int) -> MessageBuilder:
        return self

    def expires_time(self, expires_time: int) -> MessageBuilder:
        return self


class PackBuilder:

    def __init__(self, msg: JSON) -> None:
        self.__msg = msg

    async def pack(self) -> JSON:
        pass

    def did_resolver(self, did_resolver: DIDResolver) -> PackBuilder:
        pass

    def secrets_resolver(self, secrets_resolver: SecretsResolver) -> PackBuilder:
        pass

    def sign_from_did(self, from_did: DID) -> _PackBuilderSigned:
        pass

    def sign_from_kid(self, from_kid: KID) -> _PackBuilderSigned:
        pass

    def anon_crypt(self, to_dids: List[DID],
                         enc: EncAlgAnonCrypt,
                         alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        pass

    def auth_crypt_from_did(self, from_did: DID, to_dids: List[DID],
                                  enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                                  alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        pass

    def auth_crypt_from_kid(self, from_kid: KID, to_dids: List[DID],
                                  enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                                  alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        pass


class _PackBuilderSigned:

    async def pack(self) -> JSON:
        pass

    def anon_crypt(self, to_dids: List[DID],
                         enc: EncAlgAnonCrypt,
                         alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        pass

    def auth_crypt_from_did(self, from_did: DID, to_dids: List[DID],
                                  enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                                  alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        pass

    def auth_crypt_from_kid(self, from_kid: KID, to_dids: List[DID],
                                  enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                                  alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        pass


class _PackBuilderAuthCrypted:
    async def pack(self) -> JSON:
        pass

    def anon_crypt(self, to_dids: List[DID],
                         enc: EncAlgAnonCrypt,
                         alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        pass


class _PackBuilderAnonCrypted:
    async def pack(self) -> JSON:
        pass
