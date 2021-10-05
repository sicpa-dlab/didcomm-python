import json
from pathlib import Path
from typing import List, Optional

from didcomm.common.types import DID_URL
from didcomm.secrets.secrets_resolver import Secret
from didcomm.secrets.secrets_resolver_editable import SecretsResolverEditable
from didcomm.secrets.secrets_util import jwk_to_secret, secret_to_jwk_dict


class SecretsResolverDemo(SecretsResolverEditable):
    def __init__(self, file_path="secrets.json"):
        self.file_path = file_path

        if not Path(file_path).exists():
            self._secrets = {}
            self._save()

        with open(self.file_path) as f:
            jwk_keys = json.load(f)
        self._secrets = {jwk_key["kid"]: jwk_to_secret(jwk_key) for jwk_key in jwk_keys}

    def _save(self):
        with open(self.file_path, "w") as f:
            secrets_as_jwk = [secret_to_jwk_dict(s) for s in self._secrets.values()]
            json.dump(secrets_as_jwk, f)

    async def add_key(self, secret: Secret):
        self._secrets[secret.kid] = secret
        self._save()

    async def get_kids(self) -> List[str]:
        return list(self._secrets.keys())

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        return self._secrets.get(kid)

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        return [s.kid for s in self._secrets.values() if s.kid in kids]
