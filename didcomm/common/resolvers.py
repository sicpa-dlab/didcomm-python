from dataclasses import dataclass

from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver import SecretsResolver


@dataclass(frozen=True)
class ResolversConfig:
    """
    Resolvers configuration.

    Attributes:
        secrets_resolver (SecretsResolver): a _secrets resolver

        did_resolver (DIDResolver): a DID Doc resolver
    """

    secrets_resolver: SecretsResolver
    did_resolver: DIDResolver
