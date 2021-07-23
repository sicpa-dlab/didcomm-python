from abc import ABC, abstractmethod
from typing import List

from didcomm.types.types import JWK


class DIDDoc(ABC):

    @abstractmethod
    def key_agreement(self, kid: str) -> JWK:
        pass

    @abstractmethod
    def key_agreements(self, did: str) -> List[JWK]:
        pass

    @abstractmethod
    def authentication(self, kid: str) -> JWK:
        pass

    @abstractmethod
    def authentications(self, did: str) -> List[JWK]:
        pass

    @abstractmethod
    def routing_keys(self, did: str) -> List[JWK]:
        pass
