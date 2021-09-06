from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List

from didcomm.common.types import (
    DID_URL,
    DID,
    VerificationMaterial,
    VerificationMethodType,
)


class DIDDoc(ABC):
    """DID DOC abstraction (https://www.w3.org/TR/did-core/#dfn-did-documents)"""

    @property
    @abstractmethod
    def did(self) -> DID:
        """
        :return: a DID for the given DID Doc
        """
        pass

    @property
    @abstractmethod
    def key_agreement_kids(self) -> List[DID_URL]:
        """
        Key IDs (DID URLs) of all verification methods from the 'keyAgreement' verification relationship in this DID DOC.
        See https://www.w3.org/TR/did-core/#verification-methods.

        :return: a possibly empty list of key ID of all 'keyAgreement' verification methods
        """
        pass

    @property
    @abstractmethod
    def authentication_kids(self) -> List[DID_URL]:
        """
        Key IDs (DID URLs) of all verification methods from the 'authentication' verification relationship in this DID DOC.
        See https://www.w3.org/TR/did-core/#authentication.

        :return: a possibly empty list of key ID of all 'authentication' verification methods
        """
        pass

    @property
    @abstractmethod
    def verification_methods(self) -> List[VerificationMethod]:
        """
        Returns all local verification methods including embedded to key agreement and authentication sections.
        See https://www.w3.org/TR/did-core/#verification-methods.

        :return: a list of verification method instances
        """
        pass

    @property
    @abstractmethod
    def didcomm_services(self) -> List[DIDCommService]:
        """
        All services of 'DIDCommMessaging' type in this DID DOC.
        Empty list is returned if there are no services of 'DIDCommMessaging' type.
        See https://www.w3.org/TR/did-core/#services and https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.

        :return: a possibly empty list of 'DIDCommMessaging' type services
        """
        pass

    @abstractmethod
    def get_verification_method(self, id: DID_URL) -> VerificationMethod:
        """
        Returns the verification method with the given identifier.

        :param id: an identifier of a verification method
        :return: the verification method or None of there is no one for the given identifier
        """
        pass


@dataclass
class VerificationMethod:
    """
    DID DOC Verification method.
    It can be used in such verification relationships as Authentication, KeyAgreement, etc.
    See https://www.w3.org/TR/did-core/#verification-methods.

    Attributes:
        id (DID_URL): verification method `id` field
        type (VerificationMethodType): verification method `type` field as VerificationMethodType enum
        controller (str): verification method `controller` field
        verification_material (VerificationMaterial): A verification material representing a public key
    """

    id: DID_URL
    type: VerificationMethodType
    controller: str
    verification_material: VerificationMaterial


@dataclass
class DIDCommService:
    """
    DID DOC Service of 'DIDCommMessaging' type.
    See https://www.w3.org/TR/did-core/#services,
    https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint
    and https://www.w3.org/TR/did-spec-registries/#didcommmessaging

    Attributes:
        id (str): service's 'id' field
        service_endpoint (str): `serviceEndpoint` field of DIDCommMessaging service.
           It can be either a URI to be used for transport or a mediator's DID in case of alternative endpoints.
        routing_keys (List[DID_URL]): `routingKeys` field of DIDCommMessaging service.
           A possibly empty ordered array of strings referencing keys to be used when preparing the message for transmission.
        accept (List[str]): `accept` field of DIDCommMessaging service.
           A possibly empty ordered array of strings representing accepted didcomm specification versions.
    """

    id: str
    service_endpoint: str
    routing_keys: List[DID_URL]
    accept: List[str]
