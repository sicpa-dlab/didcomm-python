from abc import ABC, abstractmethod
from typing import List

from didcomm.common.types import JWK


class SecretsResolver(ABC):

    @abstractmethod
    async def get_key(self, kid: str) -> JWK:
        pass

    @abstractmethod
    async def get_keys(self, did: str) -> List[JWK]:
        pass


def register_default_secrets_resolver(secrets_resolver: SecretsResolver):
    pass
