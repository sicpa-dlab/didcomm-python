from copy import copy
from typing import List, Optional

from didcomm.common.types import DID_URL, DID
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod, DIDCommService
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver, Secret


class TestDIDDoc(DIDDoc):
    def __init__(
        self,
        did: DID,
        key_agreement_kids: List[DID_URL],
        authentication_kids: List[DID_URL],
        verification_methods: List[VerificationMethod],
        didcomm_services: List[DIDCommService],
    ):
        self._did = did
        self._key_agreement_kids = copy(key_agreement_kids)
        self._authentication_kids = copy(authentication_kids)
        self._verification_methods = copy(verification_methods)
        self._didcomm_services = copy(didcomm_services)

    def did(self) -> DID:
        return self._did

    def key_agreement_kids(self) -> List[DID_URL]:
        return self._key_agreement_kids

    def authentication_kids(self) -> List[DID_URL]:
        return self._authentication_kids

    def verification_methods(self) -> List[VerificationMethod]:
        return self._verification_methods

    def didcomm_services(self) -> List[DIDCommService]:
        return self._didcomm_services

    def get_verification_method(self, id: DID_URL) -> VerificationMethod:
        for verification_method in self._verification_methods:
            if verification_method.id == id:
                return verification_method

        return None


class TestDIDResolver(DIDResolver):
    def __init__(self, did_docs: List[DIDDoc]):
        self._did_docs = {did_doc.did(): did_doc for did_doc in did_docs}

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        return self._did_docs.get(did)


class TestSecretsResolver(SecretsResolver):
    def __init__(self, secrets: List[Secret]):
        self._secrets = {secret.kid: secret for secret in secrets}

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        return self._secrets.get(kid)

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        return list(self._secrets.keys())
