from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory


class MockSecretsResolverMediator1(MockSecretsResolverInMemory):
    def __init__(self):
        # TBD
        super().__init__(secrets=[])
