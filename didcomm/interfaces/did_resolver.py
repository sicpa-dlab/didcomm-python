from abc import ABC, abstractmethod

from didcomm.interfaces.did_doc import DIDDoc


class DIDResolver(ABC):

    @abstractmethod
    async def resolve(self, did: str) -> DIDDoc:
        pass