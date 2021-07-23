from __future__ import annotations

from typing import List

from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.algorithms import EncAlgAnonCrypt, KWAlgAnonCrypt, EncAlgAuthCrypt, KWAlgAuthCrypt
from didcomm.types.message import Message
from didcomm.types.types import JSON, DID, KID


class Packer:

    async def pack(self, msg: Message) -> JSON:
        return ""


class PackBuilder:

    def finalize(self) -> Packer:
        return Packer()

    def did_resolver(self, did_resolver: DIDResolver) -> PackBuilder:
        return self

    def secrets_resolver(self, secrets_resolver: SecretsResolver) -> PackBuilder:
        return self

    def sign(self, from_did: DID, from_kid: KID = None) -> _PackBuilderSigned:
        return _PackBuilderSigned()

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()

    def auth_crypt(self, from_did: DID, to_dids: List[DID],
                   enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                   alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW,
                   from_kid: KID = None) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()


class _PackBuilderSigned:

    def finalize(self) -> Packer:
        return Packer()

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()

    def auth_crypt(self, from_did: DID, to_dids: List[DID],
                   enc: EncAlgAuthCrypt = EncAlgAuthCrypt.A256CBC_HS512,
                   alg: KWAlgAuthCrypt = KWAlgAuthCrypt.ECDH_1PU_A256KW,
                   from_kid: KID = None) -> _PackBuilderAuthCrypted:
        return _PackBuilderAuthCrypted()


class _PackBuilderAuthCrypted:
    def finalize(self) -> Packer:
        return Packer()

    def anon_crypt(self, to_dids: List[DID],
                   enc: EncAlgAnonCrypt,
                   alg: KWAlgAnonCrypt = KWAlgAnonCrypt.ECDH_ES_A256KW) -> _PackBuilderAnonCrypted:
        return _PackBuilderAnonCrypted()


class _PackBuilderAnonCrypted:
    def finalize(self) -> Packer:
        return Packer()
