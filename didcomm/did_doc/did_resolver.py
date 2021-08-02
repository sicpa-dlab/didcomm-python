from abc import ABC, abstractmethod
from typing import List, Optional

from didcomm.did_doc.did_doc import DIDDoc


class DIDResolver(ABC):

    @abstractmethod
    async def resolve(self, did: str) -> Optional[DIDDoc]:
        pass


class DIDResolverChain(DIDResolver):

    def __init__(self, did_resolvers: List[DIDResolver]):
        self.__did_resolvers = did_resolvers

    async def resolve(self, did: str) -> Optional[DIDDoc]:
        for did_resolver in self.__did_resolvers:
            did_doc = await did_resolver.resolve(did)
            if did_doc is not None:
                return did_doc
        return None


def register_default_did_resolver(did_resolver: DIDResolver):
    pass
