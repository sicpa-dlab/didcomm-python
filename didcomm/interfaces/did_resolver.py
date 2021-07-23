from abc import ABC, abstractmethod

from didcomm.interfaces.did_doc import DIDDOC


class DIDResolver(ABC):

    @abstractmethod
    async def resolve(self, did: str) -> DIDDOC:
        pass