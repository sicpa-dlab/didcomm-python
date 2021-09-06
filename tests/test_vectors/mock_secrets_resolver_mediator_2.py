from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory


class MockSecretsResolverMediator2(SecretsResolverInMemory):
    def __init__(self):
        # TBD
        super().__init__(secrets=[])
