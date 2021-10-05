import pytest

from didcomm.secrets.secrets_resolver_demo import SecretsResolverDemo
from didcomm.secrets.secrets_util import (
    jwk_to_secret,
    generate_ed25519_keys_as_jwk_dict,
)


@pytest.fixture()
def secrets_resolver(tmp_path):
    tmp_file = tmp_path / "secrets.json"
    return SecretsResolverDemo(tmp_file)


def create_secret():
    return jwk_to_secret(generate_ed25519_keys_as_jwk_dict()[0])


@pytest.fixture()
def secrets():
    secret1 = create_secret()
    secret2 = create_secret()
    return secret1, secret2


@pytest.mark.asyncio
async def test_add_get_keys(secrets_resolver, secrets):
    secret1, secret2 = secrets

    await secrets_resolver.add_key(secret1)
    await secrets_resolver.add_key(secret2)

    assert await secrets_resolver.get_key(secret1.kid) == secret1
    assert await secrets_resolver.get_key(secret2.kid) == secret2
    assert await secrets_resolver.get_key("unknown-kid") is None
    assert await secrets_resolver.get_kids() == [secret1.kid, secret2.kid]
    assert await secrets_resolver.get_keys([secret1.kid, secret2.kid]) == [
        secret1.kid,
        secret2.kid,
    ]
    assert await secrets_resolver.get_keys([secret1.kid]) == [secret1.kid]
    assert await secrets_resolver.get_keys([secret2.kid]) == [secret2.kid]
    assert await secrets_resolver.get_keys(["unknown-kid"]) == []


@pytest.mark.asyncio
async def test_load_preserves_keys(secrets_resolver, secrets):
    secret1, secret2 = secrets

    await secrets_resolver.add_key(secret1)
    await secrets_resolver.add_key(secret2)

    secrets_resolver = SecretsResolverDemo(secrets_resolver.file_path)

    assert await secrets_resolver.get_key(secret1.kid) == secret1
    assert await secrets_resolver.get_key(secret2.kid) == secret2
    assert await secrets_resolver.get_key("unknown-kid") is None
    assert await secrets_resolver.get_kids() == [secret1.kid, secret2.kid]
    assert await secrets_resolver.get_keys([secret1.kid, secret2.kid]) == [
        secret1.kid,
        secret2.kid,
    ]
    assert await secrets_resolver.get_keys([secret1.kid]) == [secret1.kid]
    assert await secrets_resolver.get_keys([secret2.kid]) == [secret2.kid]
    assert await secrets_resolver.get_keys(["unknown-kid"]) == []
