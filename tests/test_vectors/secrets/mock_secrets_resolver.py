from typing import List, Optional

from didcomm.common.types import DID_URL
from didcomm import Secret, SecretsResolverInMemory


class MockSecretsResolverInMemory(SecretsResolverInMemory):
    def __init__(self, secrets: List[Secret]):
        self._secrets_list = secrets
        super().__init__(secrets)

    def get_key_sync(self, kid: DID_URL) -> Optional[Secret]:
        return self._secrets.get(kid)

    def get_keys_sync(self, kids: List[DID_URL]) -> List[DID_URL]:
        return [s.kid for s in self._secrets.values() if s.kid in kids]

    def get_secrets(self) -> List[Secret]:
        return self._secrets_list

    def get_secret_kids(self) -> List[DID_URL]:
        return [s.kid for s in self._secrets_list]
