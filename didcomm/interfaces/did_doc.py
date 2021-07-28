from abc import ABC, abstractmethod
from typing import List

from didcomm.types.types import JWK


class DIDDocKeyAgreement(ABC):

    @abstractmethod
    def as_jwk(self) -> JWK:
        pass


class DIDDocAuthentication(ABC):

    @abstractmethod
    def as_jwk(self) -> JWK:
        pass


class DIDDocRoutingKeys(ABC):

    @abstractmethod
    def as_jwk(self) -> JWK:
        pass


class DIDDoc(ABC):

    @abstractmethod
    def key_agreement(self, kid: str) -> DIDDocKeyAgreement:
        pass

    @abstractmethod
    def key_agreements(self, did: str) -> List[DIDDocKeyAgreement]:
        pass

    @abstractmethod
    def authentication(self, kid: str) -> DIDDocAuthentication:
        pass

    @abstractmethod
    def authentications(self, did: str) -> List[DIDDocAuthentication]:
        pass

    @abstractmethod
    def routing_keys(self, did: str) -> List[DIDDocRoutingKeys]:
        pass
