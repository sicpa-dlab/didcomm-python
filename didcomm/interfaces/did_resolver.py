from abc import ABC, abstractmethod

from didcomm.interfaces.did_doc import DIDDoc
from didcomm.types.types import DID


class DIDResolver(ABC):
    """DID resolver.

    Resolves DIDs to corresponding DID documents.
    """

    @abstractmethod
    async def resolve(self, did: DID) -> DIDDoc:
        """Resolves the specified DID to the corresponding DID document."""
        pass
