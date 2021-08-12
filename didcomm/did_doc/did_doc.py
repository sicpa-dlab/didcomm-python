from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List

from didcomm.common.types import DID_URL, DID


class DIDDoc(ABC):
    """DID DOC abstraction (https://www.w3.org/TR/did-core/#dfn-did-documents)"""

    @abstractmethod
    def did(self) -> DID:
        """
        :return: a DID for the given DID Doc
        """
        pass

    @abstractmethod
    def key_agreement_kids(self) -> List[DID_URL]:
        """
        Key IDs (DID URLs) of all verification methods from the 'keyAgreement' verification relationship in this DID DOC.
        See https://www.w3.org/TR/did-core/#verification-methods.

        :return: a possibly empty list of key ID of all 'keyAgreement' verification methods
        """
        pass

    @abstractmethod
    def authentication_kids(self) -> List[DID_URL]:
        """
        Key IDs (DID URLs) of all verification methods from the 'authentication' verification relationship in this DID DOC.
        See https://www.w3.org/TR/did-core/#authentication.

        :return: a possibly empty list of key ID of all 'authentication' verification methods
        """
        pass

    @abstractmethod
    def verification_methods(self) -> List[VerificationMethod]:
        """
        Returns all local verification methods including embedded to key agreement and authentication sections.
        See https://www.w3.org/TR/did-core/#verification-methods.

        :return: a list of verification method instances
        """
        pass

    @abstractmethod
    def didcomm_services(self) -> List[DIDCommService]:
        """
        All services of 'DIDCommMessaging' type in this DID DOC.
        Empty list is returned if there are no services of 'DIDCommMessaging' type.
        See https://www.w3.org/TR/did-core/#services and https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.

        :return: a possibly empty list of 'DIDCommMessaging' type services
        """
        pass


class VerificationMethod(ABC):
    """
    DID DOC Verification method.
    It can be used in such verification relationships as Authentication, KeyAgreement, etc.
    See https://www.w3.org/TR/did-core/#verification-methods.
    """

    @abstractmethod
    def id(self) -> str:
        """
        An ID of the verification method.
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
    def controller(self) -> str:
        """
        Verification method controller.
        :return: verification method `controller` field
        """
        pass

    @abstractmethod
    def public_key(self) -> VerificationMaterial:
        """
        A verification material representing a public key.
        Material consists of an encoding type (JWK, base58, etc.) and encoded value.

        :return: verification material instance
        """
        pass


@dataclass
class VerificationMaterial:
    type: EncodingType
    encoded_value: str


class EncodingType(Enum):
    JWK = 1
    BASE58 = 2
    OTHER = 1000


class DIDCommService(ABC):
    """
    DID DOC Service of 'DIDCommMessaging' type.
    See https://www.w3.org/TR/did-core/#services and
    https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
    """

    @abstractmethod
    def id(self) -> str:
        """
        :return: service's 'id' field
        """
        pass

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
