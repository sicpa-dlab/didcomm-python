from abc import ABC, abstractmethod
from typing import List

from didcomm.types.types import JWK


class SecretsResolver(ABC):

    @abstractmethod
    async def get_key(self, kid: str) -> JWK:
        pass

    @abstractmethod
    async def get_keys(self, did: str) -> List[JWK]:
        pass

    @abstractmethod
    async def find_keys(self, kids: List[str]) -> List[JWK]:
        pass
