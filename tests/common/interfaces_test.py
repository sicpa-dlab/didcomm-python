from typing import List

from didcomm.common.types import JWK
from didcomm.did_doc.did_doc import DIDDoc, DIDDocServiceEndpoint
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver


class TestDIDDoc(DIDDoc):

    def service_endpoints(self, did: str) -> List[DIDDocServiceEndpoint]:
        pass

    def key_agreement(self, kid: str) -> JWK:
        pass

    def key_agreements(self, did: str) -> List[JWK]:
        pass

    def authentication(self, kid: str) -> JWK:
        pass

    def authentications(self, did: str) -> List[JWK]:
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
