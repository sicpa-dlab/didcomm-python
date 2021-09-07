from typing import List, Optional

from didcomm.common.types import DID_URL
from didcomm.secrets.secrets_resolver import SecretsResolver, Secret


class SecretsResolverInMemory(SecretsResolver):
    def __init__(self, secrets: List[Secret]):
        self._secrets = {secret.kid: secret for secret in secrets}

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        return self._secrets.get(kid)

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        return [s.kid for s in self._secrets.values() if s.kid in kids]
