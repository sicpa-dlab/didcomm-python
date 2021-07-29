from typing import List

from didcomm.interfaces.did_doc import DIDDoc
from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.types import JWK


class TestDIDDoc(DIDDoc):

    def key_agreement(self, kid: str) -> JWK:
        pass

    def key_agreements(self, did: str) -> List[JWK]:
        pass

    def authentication(self, kid: str) -> JWK:
        pass

    def authentications(self, did: str) -> List[JWK]:
        pass

    def routing_keys(self, did: str) -> List[JWK]:
        pass


class TestDIDResolver(DIDResolver):

    async def resolve(self, did: str) -> DIDDoc:
        return TestDIDDoc()


class TestSecretsResolver(SecretsResolver):

    async def get_key(self, kid: str) -> JWK:
        pass

    async def get_keys(self, did: str) -> List[JWK]:
        pass

    async def find_keys(self, kids: List[str]) -> List[JWK]:
        pass
