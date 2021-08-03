from typing import List

from didcomm.common.types import JWK, DID_URL, DID
from didcomm.did_doc.did_doc import DIDDoc, DIDDocServiceEndpoint, VerificationMethod
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver


class TestDIDDoc(DIDDoc):

    def key_agreement(self, kid: DID_URL) -> VerificationMethod:
        pass

    def key_agreements(self) -> List[VerificationMethod]:
        pass

    def authentication(self, kid: DID_URL) -> VerificationMethod:
        pass

    def authentications(self) -> List[VerificationMethod]:
        pass

    def service_endpoints(self) -> List[DIDDocServiceEndpoint]:
        pass


class TestDIDResolver(DIDResolver):

    async def resolve(self, did: str) -> DIDDoc:
        return TestDIDDoc()


class TestSecretsResolver(SecretsResolver):

    async def get_key(self, kid: DID_URL) -> JWK:
        pass

    async def get_keys(self, did: DID) -> List[JWK]:
        pass
