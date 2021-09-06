from typing import List, Optional

from didcomm.common.types import DID
from didcomm.did_doc.did_doc import DIDDoc
from didcomm.did_doc.did_resolver import DIDResolver


class DIDResolverInMemory(DIDResolver):
    def __init__(self, did_docs: List[DIDDoc]):
        self._did_docs = {did_doc.did: did_doc for did_doc in did_docs}

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        return self._did_docs.get(did)
