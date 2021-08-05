from abc import ABC, abstractmethod
from typing import List, Optional

from didcomm.common.types import DID_OR_DID_URL
from didcomm.did_doc.did_doc import DIDDoc


class DIDResolver(ABC):
    """DID Resolver to resolver a DID to a DID DOC."""

    @abstractmethod
    async def resolve(self, did: DID_OR_DID_URL) -> Optional[DIDDoc]:
        """
        Resolves a DID by the given DID or DID URL.

        :param did: a DID or DID URL to be resolved
        :return: an instance of resolved DID DOC or None if the DID can not be resolved by the given resolver
        """
        pass


class DIDResolverChain(DIDResolver):
    """
    A sample implementation of a DID Resolver.

    Multiple resolvers can be registered here.
    DID resolution will be done by asking every registered resolver to resolve a DID (in the order they are passed)
    until a DID DOC is resolved.
    """

    def __init__(self, did_resolvers: List[DIDResolver]):
        self.__did_resolvers = did_resolvers

    async def resolve(self, did: DID_OR_DID_URL) -> Optional[DIDDoc]:
        """
        Resolves a DID by asking every registered resolver to resolve a DID
        (in the order they are passed to the constructor)
        until a DID DOC is resolved.

        :param did: a DID or DID URL to be resolved
        :return: an instance of resolved DID DOC or None if it can not be resolved by all of the registered resolvers.
        """

        for did_resolver in self.__did_resolvers:
            did_doc = await did_resolver.resolve(did)
            if did_doc is not None:
                return did_doc
        return None


def register_default_did_resolver(did_resolver: DIDResolver):
    """
    Registers a DID Resolver that can be used in all pack/unpack operations by default.

    :param did_resolver: a default DID resolver to be registered.
    """
    pass