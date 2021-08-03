from abc import ABC, abstractmethod
from typing import List

from didcomm.common.types import JWK, KID


class VerificationMethod(ABC):
    """
    DID DOC Verification method.
    It can be used in such verification relationships as Authentication, KeyAgreement, etc.
    """

    @abstractmethod
    def as_jwk(self) -> JWK:
        """
        A public key in JWK format.
        If the method has 'publicKeyJwk' property, that is a public key is already in JWK format, it can be returned as-is.
        If a method has a public key in another format ('publicKeyHex', 'publicKeyBase58', 'publicKeyMultibase'),
        then it must be converted to JWK format.

        :raises NoJWKKeyException: if there is no public key in the verification method, or it can not be converted to JWK format.
        :return: public key as JWK json string
        """
        pass


class DIDDocServiceEndpoint(ABC):
    """
    DID DOC Service Endpoint of 'DIDCommMessaging' type.
    """

    @abstractmethod
    def service_endpoint(self) -> str:
        """
        A service endpoint. It can be either a URI to be used for transport
        or a mediator's DID in case of alternative endpoints.

        :return: service endpoint string
        """
        pass

    @abstractmethod
    def routing_keys(self) -> List[KID]:
        """
        A possibly empty ordered array of strings referencing keys to be used when preparing the message for transmission.

        :return: a possibly empty list of key IDs
        """
        pass


class DIDDoc(ABC):
    """DID DOC abstraction resolved for a DID"""

    @abstractmethod
    def key_agreement(self, kid: KID) -> VerificationMethod:
        """
        A verification method from the 'keyAgreement' verification relationship.
        It must have 'id' equal to the  given key ID.

        :raises NoKeyAgreementException: if there is no verification method with the given key ID in 'keyAgreement'
        or there is no 'keyAgreement' relationship in this DID DOC.
        :param kid: key ID identifying verification method
        :return: verification method instance
        """
        pass

    @abstractmethod
    def key_agreements(self) -> List[VerificationMethod]:
        """
        All verification methods from the 'keyAgreement' verification relationship in this DID DOC.

        :raises NoKeyAgreementException:  if there is no 'keyAgreement' relationship in this DID DOC,
        or it has no verification methods.
        :return: a possibly empty list of verification method instances
        """
        pass

    @abstractmethod
    def authentication(self, kid: str) -> VerificationMethod:
        """
        A verification method from the 'authentication' verification relationship.
        It must have 'id' equal to the  given key ID.

        :raises NoAuthenticationException: if there is no verification method with the given key ID in 'authentication'
        or there is no 'authentication' relationship in this DID DOC.
        :param kid: key ID identifying verification method
        :return: verification method instance
        """
        pass

    @abstractmethod
    def authentications(self) -> List[VerificationMethod]:
        """
        All verification methods from the 'authentication' verification relationship in this DID DOC.

        :raises NoAuthenticationException:  if there is no 'authentication' relationship in this DID DOC,
        or it has no verification methods.
        :return: a list of verification method instances
        """
        pass

    @abstractmethod
    def service_endpoints(self) -> List[DIDDocServiceEndpoint]:
        """
        All service endpoints of 'DIDCommMessaging' type in this DID DOC.

        :raises NoDIDCommMessagingServiceEndpoints:  if there are no service endpoints of 'DIDCommMessaging' type in this DID DOC.
        :return: a list of verification method instances
        """
        pass
