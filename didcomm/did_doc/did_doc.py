from __future__ import annotations

import attr
from dataclasses import dataclass
from typing import List, Optional

from didcomm.common.types import (
    DID_URL,
    DID,
    VerificationMaterial,
    VerificationMethodType,
)
from didcomm.common.utils import search_first_in_iterable


@dataclass
class DIDDoc:
    """
    DID DOC abstraction (https://www.w3.org/TR/did-core/#dfn-did-documents)
    Attributes:
        did (str): a DID for the given DID Doc
        key_agreement_kids(List[str]): Key IDs (DID URLs) of all verification methods from the 'keyAgreement' verification relationship in this DID DOC.
                                       See https://www.w3.org/TR/did-core/#verification-methods.
        authentication_kids(List[str]): Key IDs (DID URLs) of all verification methods from the 'authentication' verification relationship in this DID DOC.
                                        See https://www.w3.org/TR/did-core/#authentication.
        verification_methods(List[VerificationMethod): All local verification methods including embedded to key agreement and authentication sections.
                                                       See https://www.w3.org/TR/did-core/#verification-methods.
        didcomm_services(List[DIDCommService]): All services of 'DIDCommMessaging' type in this DID DOC.
                                                Empty list is returned if there are no services of 'DIDCommMessaging' type.
                                                See https://www.w3.org/TR/did-core/#services and
                                                https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
    """

    did: DID
    key_agreement_kids: List[DID_URL]
    authentication_kids: List[DID_URL]
    verification_methods: List[VerificationMethod]
    didcomm_services: List[DIDCommService]

    def get_verification_method(self, id: DID_URL) -> Optional[VerificationMethod]:
        """
        Returns the verification method with the given identifier.

        :param id: an identifier of a verification method
        :return: the verification method or None of there is no one for the given identifier
        """
        return search_first_in_iterable(self.verification_methods, lambda x: x.id == id)

    def get_didcomm_service(self, id: str) -> Optional[DIDCommService]:
        """
        Returns DID Document service endpoint with the given identifier.

        :param id: an identifier of a service endpoint
        :return: the service endpoint or None of there is no one for the given identifier
        """
        return search_first_in_iterable(self.didcomm_services, lambda x: x.id == id)


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


# might makes sense for future
# def converter__DIDDocServiceTypes(service_t: Union[str, Any]):
#     return (
#         DIDDocServiceTypes(service_t)
#         if isinstance(service_t, str) else service_t
#     )


@attr.s(auto_attribs=True)
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

    id: str = attr.ib(validator=attr.validators.instance_of(str))
    service_endpoint: str = attr.ib(validator=attr.validators.instance_of(str))
    # TODO validate each item (should be did-url)
    routing_keys: List[DID_URL] = attr.ib(validator=attr.validators.instance_of(list))
    # TODO validate each item (should be str)
    accept: List[str] = attr.ib(validator=attr.validators.instance_of(list))
