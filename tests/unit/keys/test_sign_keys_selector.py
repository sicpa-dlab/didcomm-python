import pytest

from didcomm.core.keys.sign_keys_selector import find_signing_key, find_verification_key
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import (
    DIDDocNotResolvedError,
    SecretNotFoundError,
    DIDUrlNotFoundError,
)
from didcomm.secrets.secrets_resolver import Secret
from tests.test_vectors.common import ALICE_DID
from tests.test_vectors.utils import (
    Person,
    get_auth_secrets,
    get_auth_methods_not_in_secrets,
    get_auth_methods,
)


@pytest.mark.asyncio
async def test_find_signing_key_by_did_positive(resolvers_config_alice):
    secret = await find_signing_key(ALICE_DID, resolvers_config_alice)
    # the first found secret is returned
    assert secret == get_auth_secrets(Person.ALICE)[0]


@pytest.mark.asyncio
async def test_find_signing_key_by_kid_positive(resolvers_config_alice):
    for secret in get_auth_secrets(Person.ALICE):
        await check_find_signing_key_by_kid(secret, resolvers_config_alice)


async def check_find_signing_key_by_kid(
    expected_secret: Secret, resolvers_config_alice
):
    assert (
        await find_signing_key(expected_secret.kid, resolvers_config_alice)
        == expected_secret
    )


@pytest.mark.asyncio
async def test_find_signing_key_by_did_unknown_did(resolvers_config_alice):
    with pytest.raises(DIDDocNotResolvedError):
        await find_signing_key("did:example:unknown", resolvers_config_alice)


@pytest.mark.asyncio
async def test_find_signing_key_by_kid_unknown_did(resolvers_config_alice):
    with pytest.raises(SecretNotFoundError):
        await find_signing_key("did:example:unknown#key-1", resolvers_config_alice)


@pytest.mark.asyncio
async def test_find_signing_key_by_kid_secret_not_found(resolvers_config_alice):
    for vm in get_auth_methods_not_in_secrets(Person.ALICE):
        with pytest.raises(SecretNotFoundError):
            await find_signing_key(vm.id, resolvers_config_alice)


@pytest.mark.asyncio
async def test_find_signing_key_by_kid_unknown_kid(resolvers_config_alice):
    with pytest.raises(SecretNotFoundError):
        await find_signing_key(ALICE_DID + "#unknown-key-1", resolvers_config_alice)


@pytest.mark.asyncio
async def test_find_verification_key_positive(resolvers_config_alice):
    for vm in get_auth_methods(Person.ALICE):
        await check_find_verification_key_by_kid(vm, resolvers_config_alice)


async def check_find_verification_key_by_kid(
    expected_ver_method: VerificationMethod, resolvers_config_alice
):
    verification_method = await find_verification_key(
        expected_ver_method.id, resolvers_config_alice
    )
    assert verification_method == expected_ver_method


@pytest.mark.asyncio
async def test_find_verification_key_unknown_did(resolvers_config_alice):
    with pytest.raises(DIDDocNotResolvedError):
        await find_verification_key("did:example:unknown#key-1", resolvers_config_alice)


@pytest.mark.asyncio
async def test_find_verification_key_unknown_kid(resolvers_config_alice):
    with pytest.raises(DIDUrlNotFoundError):
        await find_verification_key(
            ALICE_DID + "#unknown-key-1", resolvers_config_alice
        )
