from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory
from tests.test_vectors.secrets.mock_secrets_resolver_alice import (
    ALICE_SECRET_AUTH_KEY_ED25519,
    ALICE_SECRET_AUTH_KEY_P256,
    ALICE_SECRET_AUTH_KEY_SECP256K1,
    ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
    ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
)
from tests.test_vectors.secrets.mock_secrets_resolver_charlie import (
    CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
    CHARLIE_SECRET_AUTH_KEY_ED25519,
)


class MockSecretsResolverCharlieRotatedToAlice(MockSecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                CHARLIE_SECRET_KEY_AGREEMENT_KEY_X25519,
                CHARLIE_SECRET_AUTH_KEY_ED25519,
                ALICE_SECRET_AUTH_KEY_ED25519,
                ALICE_SECRET_AUTH_KEY_P256,
                ALICE_SECRET_AUTH_KEY_SECP256K1,
                ALICE_SECRET_KEY_AGREEMENT_KEY_X25519,
                ALICE_SECRET_KEY_AGREEMENT_KEY_P256,
                ALICE_SECRET_KEY_AGREEMENT_KEY_P521,
            ]
        )
