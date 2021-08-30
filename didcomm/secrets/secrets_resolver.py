from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from didcomm.common.types import DID_URL, VerificationMethodType, VerificationMaterial


@dataclass
class Secret:
    """
    A secret (private key) abstraction.

    Attributes:
        kid (str): a key ID identifying a secret (private key).
          Must have the same value, as key ID ('id' field) of the corresponding method in DID Doc containing a public key.

        type (VerificationMethodType): secret (private key) type.
          Must have the same value, as type ('type' field as VerificationMethodType enum) of the corresponding method in DID Doc containing a public key.

        verification_material (VerificationMaterial): A verification material representing a private key.
    """

    kid: DID_URL
    type: VerificationMethodType
    verification_material: VerificationMaterial


class SecretsResolver(ABC):
    """Resolves _secrets such as private keys to be used for signing and encryption."""

    @abstractmethod
    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        """
        Finds d private key identified by the given key ID.

        :param kid: the key ID identifying a private key
        :return: a private key or None of there is no key for the given key ID
        """
        pass

    @abstractmethod
    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        """
        Find all private keys that have one of the given key IDs.
        Return keys only for key IDs for which a key is present.

        :param kids: the key IDs find private keys for
        :return: a possible empty list of all private keys that have one of the given keyIDs.
        """
        pass
