import copy

import pytest

from didcomm.errors import (
    DIDCommValueError,
    DIDDocNotResolvedError,
    SecretNotFoundError,
    DIDUrlNotFoundError,
)
from didcomm.pack_encrypted import pack_encrypted
from tests.test_vectors.common import TEST_MESSAGE, BOB_DID, CHARLIE_DID, ALICE_DID
from tests.test_vectors.utils import get_key_agreement_methods_in_secrets, Person


@pytest.mark.asyncio
async def test_from_is_not_a_did_or_did_url(resolvers_config_alice):
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            frm="not-a-did",
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_is_not_a_did_or_did_url(resolvers_config_alice):
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            to="not-a-did",
        )


@pytest.mark.asyncio
async def test_from_differs_from_msg_from(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.frm = CHARLIE_DID
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm=ALICE_DID,
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_differs_from_msg_to(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = [CHARLIE_DID]
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm=ALICE_DID,
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_present_in_msg_to(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = [BOB_DID, CHARLIE_DID]
    await pack_encrypted(
        resolvers_config=resolvers_config_alice, message=msg, frm=ALICE_DID, to=BOB_DID
    )


@pytest.mark.asyncio
async def test_from_is_not_a_did_or_did_url_in_msg(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.frm = "not-a-did"
    with pytest.raises(DIDDocNotResolvedError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm="not-a-did",
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_is_not_a_did_or_did_url_in_msg(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = ["not-a-did"]
    with pytest.raises(DIDDocNotResolvedError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            to="not-a-did",
        )


@pytest.mark.asyncio
async def test_from_param_is_url_from_msg_is_did(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.frm = ALICE_DID
    await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=msg,
        frm=get_key_agreement_methods_in_secrets(Person.ALICE)[0].id,
        to=BOB_DID,
    )


@pytest.mark.asyncio
async def test_to_param_is_url_to_msg_is_did(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = [ALICE_DID, BOB_DID]
    await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=msg,
        to=get_key_agreement_methods_in_secrets(Person.BOB)[0].id,
    )


@pytest.mark.asyncio
async def test_from_param_is_did_from_msg_is_did_url(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.frm = get_key_agreement_methods_in_secrets(Person.ALICE)[0].id
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm=ALICE_DID,
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_param_is_did_to_msg_is_did_url(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = [get_key_agreement_methods_in_secrets(Person.BOB)[0].id]
    with pytest.raises(DIDCommValueError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice, message=msg, to=BOB_DID
        )


@pytest.mark.asyncio
async def test_from_unknown_did(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.frm = "did:example:unknown"
    with pytest.raises(DIDDocNotResolvedError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm="did:example:unknown",
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_from_unknowndid_url(resolvers_config_alice):
    with pytest.raises(SecretNotFoundError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            frm=ALICE_DID + "#unknown-key",
            to=BOB_DID,
        )


@pytest.mark.asyncio
async def test_to_unknown_did(resolvers_config_alice):
    msg = copy.deepcopy(TEST_MESSAGE)
    msg.to = ["did:example:unknown"]
    with pytest.raises(DIDDocNotResolvedError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=msg,
            frm=ALICE_DID,
            to="did:example:unknown",
        )


@pytest.mark.asyncio
async def test_to_unknown_did_url(resolvers_config_alice):
    with pytest.raises(DIDUrlNotFoundError):
        await pack_encrypted(
            resolvers_config=resolvers_config_alice,
            message=TEST_MESSAGE,
            frm=ALICE_DID,
            to=BOB_DID + "#unknown-key",
        )
