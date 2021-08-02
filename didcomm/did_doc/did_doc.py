from abc import ABC, abstractmethod
from typing import List, Optional

from didcomm.common.types import JWK


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


class DIDDocServiceEndpoint(ABC):

    @abstractmethod
    def service_endpoint(self) -> str:
        pass

    @abstractmethod
    def routing_keys(self, did: str) -> List[DIDDocRoutingKeys]:
        pass


class DIDDoc(ABC):

    @abstractmethod
    def key_agreement(self, kid: str) -> Optional[DIDDocKeyAgreement]:
        pass

    @abstractmethod
    def key_agreements(self, did: str) -> List[DIDDocKeyAgreement]:
        pass

    @abstractmethod
    def authentication(self, kid: str) -> Optional[DIDDocAuthentication]:
        pass

    @abstractmethod
    def authentications(self, did: str) -> List[DIDDocAuthentication]:
        pass

    @abstractmethod
    def service_endpoints(self, did: str) -> List[DIDDocServiceEndpoint]:
        pass
