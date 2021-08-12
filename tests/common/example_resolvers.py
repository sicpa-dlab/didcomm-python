from typing import List, Optional

from didcomm.common.types import DID_URL, DID
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver, Secret


class ExampleDIDDoc(DIDDoc):

    def did(self) -> DID:
        pass

    def key_agreement_kids(self) -> List[DID_URL]:
        pass

    def authentication_kids(self) -> List[DID_URL]:
        pass

    def verification_methods(self) -> List[VerificationMethod]:
        pass

    def didcomm_services(self) -> List[DIDCommService]:
        pass


class ExampleDIDResolver(DIDResolver):

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        return ExampleDIDDoc()


class ExampleSecretsResolver(SecretsResolver):

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        pass

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        pass
