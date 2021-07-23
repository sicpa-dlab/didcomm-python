from __future__ import annotations

from typing import List

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.algorithms import EncAlgAnonCrypt, KWAlgAnonCrypt, EncAlgAuthCrypt, KWAlgAuthCrypt
from didcomm.types.message import Message
from didcomm.types.types import JSON, DID, KID


class PackBuilder:

    def __init__(self, msg: Message) -> None:
        self.__msg = msg

    async def pack(self) -> JSON:
        return ""

    def did_resolver(self, did_resolver: DIDResolver) -> PackBuilder:
        return self

    def secrets_resolver(self, secrets_resolver: SecretsResolver) -> PackBuilder:
        return self

    def sign_from_did(self, from_did: DID) -> _PackBuilderSigned:
        return _PackBuilderSigned()

    def sign_from_kid(self, from_kid: KID) -> _PackBuilderSigned:
        return _PackBuilderSigned()

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()

    def auth_crypt_from_did(self, from_did: DID, to_dids: List[DID],
                            enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                            alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()

    def auth_crypt_from_kid(self, from_kid: KID, to_dids: List[DID],
                            enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                            alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()


class _PackBuilderSigned:

    async def pack(self) -> JSON:
        return ""

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()

    def auth_crypt_from_did(self, from_did: DID, to_dids: List[DID],
                            enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                            alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()

    def auth_crypt_from_kid(self, from_kid: KID, to_dids: List[DID],
                            enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                            alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()


class _PackBuilderAuthCrypted:
    async def pack(self) -> JSON:
        return ""

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()


class _PackBuilderAnonCrypted:
    async def pack(self) -> JSON:
        return ""
