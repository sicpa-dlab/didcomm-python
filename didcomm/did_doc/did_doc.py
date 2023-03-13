from __future__ import annotations

from typing import Optional

from pydid import DIDCommService
from pydid import VerificationMethod
from pydid.doc import DIDDocument

from didcomm.common.types import DID_URL
from didcomm.common.utils import search_first_in_iterable


class DIDDoc(DIDDocument):
    def get_verification_method(self, id: DID_URL) -> Optional[VerificationMethod]:
        """
        Returns the verification method with the given identifier.

        :param id: an identifier of a verification method
        :return: the verification method or None of there is no one for the given identifier
        """
        return (
            search_first_in_iterable(self.verification_method, lambda x: x.id == id)
            if self.verification_method
            else None
        )

    def get_didcomm_service(self, id: str) -> Optional[DIDCommService]:
        """
        Returns DID Document service endpoint with the given identifier.

        :param id: an identifier of a service endpoint
        :return: the service endpoint or None of there is no one for the given identifier
        """
        return (
            search_first_in_iterable(self.service, lambda x: x.id == id)
            if self.service
            else None
        )
