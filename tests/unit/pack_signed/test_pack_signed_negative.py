import pytest

from didcomm.errors import (
    DIDCommValueError,
    DIDDocNotResolvedError,
    SecretNotFoundError,
)
from didcomm.pack_signed import pack_signed
from tests.test_vectors.common import ALICE_DID
from tests.test_vectors.didcomm_messages.messages import TEST_MESSAGE
from tests.test_vectors.utils import get_auth_methods_not_in_secrets, Person


@pytest.mark.asyncio
async def test_from_is_not_a_did_or_did_url(resolvers_config_alice):
    with pytest.raises(DIDCommValueError):
        await pack_signed(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            sign_frm="not-a-did",
        )


@pytest.mark.asyncio
async def test_from_unknown_did(resolvers_config_alice):
    with pytest.raises(DIDDocNotResolvedError):
        await pack_signed(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            sign_frm="did:example:unknown",
        )


@pytest.mark.asyncio
async def test_from_unknown_did_url(resolvers_config_alice):
    with pytest.raises(SecretNotFoundError):
        await pack_signed(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            sign_frm=ALICE_DID + "#unknown-key",
        )


@pytest.mark.asyncio
async def test_from_not_in_secrets(resolvers_config_alice):
    frm = get_auth_methods_not_in_secrets(Person.ALICE)[0].id
    with pytest.raises(SecretNotFoundError):
        await pack_signed(
            resolvers_config=resolvers_config_alice, message=TEST_MESSAGE, sign_frm=frm
        )
