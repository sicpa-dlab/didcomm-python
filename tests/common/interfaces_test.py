from typing import List

from didcomm.interfaces.did_doc import DIDDoc, VerificationMethod
from didcomm.interfaces.did_resolver import DIDResolver
from didcomm.interfaces.secrets_resolver import SecretsResolver
from didcomm.types.types import JWK, KID, DID


class TestVerificationMethod(VerificationMethod):

    def as_jwk(self) -> JWK:
        return ""


class TestDIDDoc(DIDDoc):

    def key_agreement(self, kid: KID) -> VerificationMethod:
        return TestVerificationMethod()

    def key_agreements(self) -> List[VerificationMethod]:
        return [TestVerificationMethod()]

    def authentication(self, kid: KID) -> VerificationMethod:
        return TestVerificationMethod()

    def authentications(self) -> List[VerificationMethod]:
        return [TestVerificationMethod()]

    def routing_keys(self) -> List[VerificationMethod]:
        return [TestVerificationMethod()]


class TestDIDResolver(DIDResolver):

    async def resolve(self, did: DID) -> DIDDoc:
        return TestDIDDoc()


class TestSecretsResolver(SecretsResolver):

    async def get_key(self, kid: KID) -> JWK:
        return ""

    async def get_keys(self, did: DID) -> List[JWK]:
        return [""]

    async def find_keys(self, kids: List[KID]) -> List[JWK]:
        return [""]
