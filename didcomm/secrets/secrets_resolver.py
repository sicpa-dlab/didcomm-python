from abc import ABC, abstractmethod
from typing import List

from didcomm.common.types import JWK


class SecretsResolver(ABC):
    """Resolves secrets such as private keys to be used for signing and encryption."""

    @abstractmethod
    async def get_key(self, kid: str) -> JWK:
        """
        A private key identified by the given key ID.

        :raises NoJWKKeyException: if there is no key for the given key ID
        :param kid: the key ID identifying a private key
        :return: a private key in JWK format
        """
        pass

    @abstractmethod
    async def get_keys(self, did: str) -> List[JWK]:
        """
        All private keys for the given DID

        :param did: the DID get all private keys for
        :return: a possible empty list of all private keys for the given DID in JWK format
        """
        pass


def register_default_secrets_resolver(secrets_resolver: SecretsResolver):
    """
    Registers a Secrets Resolver that can be used in all pack/unpack operations by default.

    :param secrets_resolver: a default secrets resolver to be registered.
    """
    pass
