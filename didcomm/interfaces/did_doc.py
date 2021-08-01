from abc import ABC, abstractmethod
from typing import List

from didcomm.types.types import JWK, KID, DID


class VerificationMethod(ABC):
    """Verification method."""

    @abstractmethod
    def as_jwk(self) -> JWK:
        """Returns the JWK of this verification method."""
        pass


class DIDDoc(ABC):
    """DID Document."""

    @abstractmethod
    def key_agreement(self, kid: KID) -> VerificationMethod:
        """Gets keyAgreement verification method by the specified key ID."""
        pass

    @abstractmethod
    def key_agreements(self) -> List[VerificationMethod]:
        """Gets all keyAgreement verification methods from this DID document."""
        pass

    @abstractmethod
    def authentication(self, kid: KID) -> VerificationMethod:
        """Gets authentication verification method by the specified key ID."""
        pass

    @abstractmethod
    def authentications(self) -> List[VerificationMethod]:
        """Gets all keyAgreement verification methods from this DID document."""
        pass

    @abstractmethod
    def routing_keys(self, did: DID) -> List[VerificationMethod]:
        """Gets all routingKeys verification methods from this DID document."""
        pass
