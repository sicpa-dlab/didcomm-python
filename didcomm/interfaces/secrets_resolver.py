from abc import ABC, abstractmethod
from typing import List

from didcomm.types.types import JWK, KID, DID


class SecretsResolver(ABC):
    """Secrets resolver.

    Retrieves JWKs with private keys for DIDs of key IDs.
    """

    @abstractmethod
    async def get_key(self, kid: KID) -> JWK:
        """Gets the JWK with the private key by the specified key ID."""
        pass

    @abstractmethod
    async def get_keys(self, did: DID) -> List[JWK]:
        """Gets all the JWKs with private keys for the specified DID."""
        pass

    @abstractmethod
    async def find_keys(self, kids: List[KID]) -> List[JWK]:
        """Finds the JWKs with private keys by the specified key IDs."""
        pass
