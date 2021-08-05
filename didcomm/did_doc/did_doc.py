from abc import ABC, abstractmethod
from typing import List, Optional

from didcomm.common.types import DID_URL, DID


class VerificationMethod(ABC):
    """
    DID DOC Verification method.
    It can be used in such verification relationships as Authentication, KeyAgreement, etc.
    """

    @abstractmethod
    def kid(self) -> str:
        """
        A key ID of the verification method.
        :return: verification method `id` field
        """
        pass

    @abstractmethod
    def type(self) -> str:
        """
        Verification method type.
        :return: verification method `type` field
        """
        pass

    @abstractmethod
    def public_key(self) -> str:
        """
        A public key of the method.

        The value is type-specific.
        For example, for 'JsonWebKey2020' type it will be the value of `publicKeyJwk` field as a JSON sting.
        For 'X25519KeyAgreementKey2019' type it will be the value of `publicKeyBase58` field as a base58-encoded string.

        :return: type-specific value of the public key a string
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
    def routing_keys(self) -> List[DID_URL]:
        """
        A possibly empty ordered array of strings referencing keys to be used when preparing the message for transmission.

        :return: a possibly empty list of key IDs
        """
        pass


class DIDDoc(ABC):
    """DID DOC abstraction resolved for a DID"""

    @abstractmethod
    def did(self) -> DID:
        """
        :return: a DID for the given DID Doc
        """
        pass

    @abstractmethod
    def key_agreement_kids(self) -> List[DID_URL]:
        """
        Key IDs of all verification methods from the 'keyAgreement' verification relationship in this DID DOC.

        :return: a possibly empty list of key ID of all 'keyAgreement' verification methods
        """
        pass

    @abstractmethod
    def authentication_kids(self) -> List[DID_URL]:
        """
        Key IDs of all verification methods from the 'authentication' verification relationship in this DID DOC.

        :return: a possibly empty list of key ID of all 'authentication' verification methods
        """
        pass

    @abstractmethod
    def verification_method(self, kid: DID_URL) -> Optional[VerificationMethod]:
        """
        A verification method with the given 'id' (key ID).
        In most of the cases it will be a verification method from 'authentication' or 'keyAgreement' verification relationship.

        :param kid: key ID of a verification method
        :return: a verification method identified by the given key ID
        or None if there is no method with the given key ID.
        """
        pass

    @abstractmethod
    def service_endpoints(self) -> List[DIDDocServiceEndpoint]:
        """
        All service endpoints of 'DIDCommMessaging' type in this DID DOC.
        Empty list is returned if there are no service endpoints of 'DIDCommMessaging' type.

        :return: a possibly empty list of 'DIDCommMessaging' type service endpoints
        """
        pass
