from typing import List

from didcomm.interfaces.did_doc import DIDDoc
from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.types import JWK, KID, DID


class TestDIDDoc(DIDDoc):

    def key_agreement(self, kid: KID) -> JWK:
        pass

    def key_agreements(self, did: DID) -> List[JWK]:
        pass

    def authentication(self, kid: KID) -> JWK:
        pass

    def authentications(self, did: DID) -> List[JWK]:
        pass

    def routing_keys(self, did: DID) -> List[JWK]:
        pass


class TestDIDResolver(DIDResolver):

    async def resolve(self, did: DID) -> DIDDoc:
        return TestDIDDoc()


class TestSecretsResolver(SecretsResolver):

    async def get_key(self, kid: KID) -> JWK:
        pass

    async def get_keys(self, did: DID) -> List[JWK]:
        pass

    async def find_keys(self, kids: List[KID]) -> List[JWK]:
        pass
