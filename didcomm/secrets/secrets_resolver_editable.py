from abc import abstractmethod
from typing import List

from didcomm.secrets.secrets_resolver import SecretsResolver, Secret


class SecretsResolverEditable(SecretsResolver):
    @abstractmethod
    async def add_key(self, secret: Secret):
        pass

    @abstractmethod
    async def get_kids(self) -> List[str]:
        pass
