from dataclasses import dataclass

from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver


# TODO: Decide if we want to provide a possiblity to register default resolvers,
# or it's better to always pass ResolversConfig explicitly to every pack/sign/unpack/etc. methods.

def register_default_did_resolver(did_resolver: DIDResolver):
    """
    Registers a DID Resolver that can be used in all pack/unpack operations by default.

    :param did_resolver: a default DID resolver to be registered.
    """
    pass


def register_default_secrets_resolver(secrets_resolver: SecretsResolver):
    """
    Registers a Secrets Resolver that can be used in all pack/unpack operations by default.

    :param secrets_resolver: a default secrets resolver to be registered.
    """
    pass


@dataclass(frozen=True)
class ResolversConfig:
    """
    Resolvers configuration.

    Attributes:
        secrets_resolver (SecretsResolver): an optional secrets resolver that can override a default secrets resolver
        registered by 'register_default_secrets_resolver'

        did_resolver (DIDResolver): an optional DID Doc resolver that can override a default DID Doc resolver
        registered by 'register_default_did_resolver'
    """
    secrets_resolver: SecretsResolver = None
    did_resolver: DIDResolver = None
