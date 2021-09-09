from typing import List

import pytest

from didcomm.common.types import DID_URL
from didcomm.core.keys.authcrypt_keys_selector import (
    find_authcrypt_pack_sender_and_recipient_keys,
    AuthcryptPackKeys,
    find_authcrypt_unpack_sender_and_recipient_keys,
    AuthcryptUnpackKeys,
)
from didcomm.did_doc.did_doc import VerificationMethod
from didcomm.errors import (
    DIDDocNotResolvedError,
    DIDUrlNotFoundError,
    SecretNotFoundError,
    IncompatibleCryptoError,
)
from tests.test_vectors.common import BOB_DID, ALICE_DID
from tests.test_vectors.utils import (
    get_key_agreement_methods,
    get_key_agreement_secrets,
    Person,
    KeyAgreementCurveType,
    get_key_agreement_methods_not_in_secrets,
    get_key_agreement_methods_in_secrets,
)


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_by_did_positive(
    resolvers_config_alice,
):
    # expect all keys of the same type as the first key
    expected = AuthcryptPackKeys(
        sender_private_key=get_key_agreement_secrets(Person.ALICE)[0],
        recipient_public_keys=get_key_agreement_methods(
            Person.BOB, KeyAgreementCurveType.X25519
        ),
    )
    res = await find_authcrypt_pack_sender_and_recipient_keys(
        ALICE_DID, BOB_DID, resolvers_config_alice
    )
    assert res == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_pack_sender_and_recipient_keys_sender_by_kid_recipient_by_did_positive(
    curve_type, resolvers_config_alice
):
    # expect all keys of the same type as the first key
    expected_sender_key = get_key_agreement_secrets(Person.ALICE, curve_type)[0]
    expected_recipient_public_keys = get_key_agreement_methods(Person.BOB, curve_type)
    expected = AuthcryptPackKeys(expected_sender_key, expected_recipient_public_keys)
    res = await find_authcrypt_pack_sender_and_recipient_keys(
        expected_sender_key.kid, BOB_DID, resolvers_config_alice
    )
    assert res == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_pack_sender_and_recipient_keys_sender_and_recipient_by_kid_positive(
    curve_type, resolvers_config_alice
):
    expected_sender_key = get_key_agreement_secrets(Person.ALICE, curve_type)[0]
    expected_recipient_public_key = get_key_agreement_methods(Person.BOB, curve_type)[1]
    expected = AuthcryptPackKeys(expected_sender_key, [expected_recipient_public_key])
    res = await find_authcrypt_pack_sender_and_recipient_keys(
        expected_sender_key.kid,
        expected_recipient_public_key.id,
        resolvers_config_alice,
    )
    assert res == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_pack_sender_and_recipient_keys_sender_by_did_recipient_by_kid_positive(
    curve_type, resolvers_config_alice
):
    expected_sender_key = get_key_agreement_secrets(Person.ALICE, curve_type)[0]
    expected_recipient_public_key = get_key_agreement_methods(Person.BOB, curve_type)[1]
    expected = AuthcryptPackKeys(expected_sender_key, [expected_recipient_public_key])
    res = await find_authcrypt_pack_sender_and_recipient_keys(
        ALICE_DID, expected_recipient_public_key.id, resolvers_config_alice
    )
    assert res == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_pack_sender_and_recipient_keys_recipient_kid_not_in_secret(
    curve_type, resolvers_config_alice
):
    expected_sender_key = get_key_agreement_secrets(Person.ALICE, curve_type)[0]
    expected_recipient_public_key = get_key_agreement_methods_not_in_secrets(
        Person.BOB, curve_type
    )[0]
    expected = AuthcryptPackKeys(expected_sender_key, [expected_recipient_public_key])
    res = await find_authcrypt_pack_sender_and_recipient_keys(
        expected_sender_key.kid,
        expected_recipient_public_key.id,
        resolvers_config_alice,
    )
    assert res == expected


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_unknown_sender_did(
    resolvers_config_alice,
):
    with pytest.raises(DIDDocNotResolvedError):
        await find_authcrypt_pack_sender_and_recipient_keys(
            "did:example:unknown", BOB_DID, resolvers_config_alice
        )


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_unknown_recipient_did(
    resolvers_config_alice,
):
    with pytest.raises(DIDDocNotResolvedError):
        await find_authcrypt_pack_sender_and_recipient_keys(
            ALICE_DID, "did:example:unknown", resolvers_config_alice
        )


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_unknown_sender_kid(
    resolvers_config_alice,
):
    with pytest.raises(SecretNotFoundError):
        await find_authcrypt_pack_sender_and_recipient_keys(
            ALICE_DID + "#unknown-key", BOB_DID, resolvers_config_alice
        )


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_unknown_recipient_kid(
    resolvers_config_alice,
):
    with pytest.raises(DIDUrlNotFoundError):
        await find_authcrypt_pack_sender_and_recipient_keys(
            ALICE_DID, BOB_DID + "#unknown-key", resolvers_config_alice
        )


@pytest.mark.asyncio
async def test_find_authcrypt_pack_sender_and_recipient_keys_sender_kid_not_in_secrets(
    resolvers_config_alice,
):
    with pytest.raises(SecretNotFoundError):
        sender_kid = get_key_agreement_methods_not_in_secrets(Person.ALICE)[0].id
        await find_authcrypt_pack_sender_and_recipient_keys(
            sender_kid, BOB_DID, resolvers_config_alice
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type_sender",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
@pytest.mark.parametrize(
    "curve_type_recipient",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_pack_sender_and_recipient_keys_different_curve_types(
    curve_type_sender, curve_type_recipient, resolvers_config_alice
):
    if curve_type_sender == curve_type_recipient:
        return
    frm_kid = get_key_agreement_methods_in_secrets(Person.ALICE, curve_type_sender)[
        0
    ].id
    to_kid = get_key_agreement_methods_in_secrets(Person.BOB, curve_type_recipient)[
        0
    ].id
    with pytest.raises(IncompatibleCryptoError):
        await find_authcrypt_pack_sender_and_recipient_keys(
            frm_kid, to_kid, resolvers_config_alice
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_unpack_sender_and_recipient_keys_recipient_kids_in_secrets_same_type_positive(
    curve_type, resolvers_config_bob
):
    for sender_vm in get_key_agreement_methods(Person.ALICE, curve_type):
        to_kids = [s.kid for s in get_key_agreement_secrets(Person.BOB, curve_type)]
        await check_find_authcrypt_unpack_sender_and_recipient_keys(
            sender_vm, to_kids, curve_type, resolvers_config_bob
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_unpack_sender_and_recipient_keys_all_recipient_kids_same_type_positive(
    curve_type, resolvers_config_bob
):
    for sender_vm in get_key_agreement_methods(Person.ALICE, curve_type):
        to_kids = [vm.id for vm in get_key_agreement_methods(Person.BOB, curve_type)]
        await check_find_authcrypt_unpack_sender_and_recipient_keys(
            sender_vm, to_kids, curve_type, resolvers_config_bob
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "sender_curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_unpack_sender_and_recipient_keys_all_recipient_kids_all_types_positive(
    sender_curve_type, resolvers_config_bob
):
    for sender_vm in get_key_agreement_methods(Person.ALICE, sender_curve_type):
        to_kids = [
            vm.id
            for vm in get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.ALL)
        ]
        await check_find_authcrypt_unpack_sender_and_recipient_keys(
            sender_vm, to_kids, sender_curve_type, resolvers_config_bob
        )


async def check_find_authcrypt_unpack_sender_and_recipient_keys(
    sender_vm: VerificationMethod,
    to_kids: List[DID_URL],
    curve_type,
    resolvers_config_bob,
):
    recipient_secrets = get_key_agreement_secrets(Person.BOB, curve_type)
    expected = [
        AuthcryptUnpackKeys(recipient_secret, sender_vm)
        for recipient_secret in recipient_secrets
    ]
    res = [
        r
        async for r in find_authcrypt_unpack_sender_and_recipient_keys(
            sender_vm.id, to_kids, resolvers_config_bob
        )
    ]
    assert res == expected


@pytest.mark.asyncio
async def test_find_authcrypt_unpack_sender_and_recipient_keys_unknown_sender_did(
    resolvers_config_bob,
):
    frm_kid = "did:example:unknown#key-1"
    to_kids = [
        vm.id
        for vm in get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.X25519)
    ]
    with pytest.raises(DIDDocNotResolvedError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
async def test_find_authcrypt_unpack_sender_and_recipient_keys_unknown_sender_kid(
    resolvers_config_bob,
):
    frm_kid = ALICE_DID + "#unknown-key-1"
    to_kids = [
        vm.id
        for vm in get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.X25519)
    ]
    with pytest.raises(DIDUrlNotFoundError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
async def test_find_authcrypt_unpack_sender_and_recipient_keys_unknown_recipient_did(
    resolvers_config_bob,
):
    frm_kid = get_key_agreement_methods(Person.ALICE)[0].id
    to_kids = ["did:example:unknown#key-1", "did:example:unknown#key-2"]
    with pytest.raises(DIDUrlNotFoundError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
async def test_find_authcrypt_unpack_sender_and_recipient_keys_unknown_recipient_kid(
    resolvers_config_bob,
):
    frm_kid = get_key_agreement_methods(Person.ALICE)[0].id
    to_kids = [BOB_DID + "#unknown-1", BOB_DID + "#unknown-2"]
    with pytest.raises(DIDUrlNotFoundError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.ALL,
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_unpack_sender_and_recipient_keys_recipient_kids_not_in_secrets(
    curve_type, resolvers_config_bob
):
    frm_kid = get_key_agreement_methods(Person.ALICE)[0].id
    to_kids = [
        vm.id for vm in get_key_agreement_methods_not_in_secrets(Person.BOB, curve_type)
    ]
    with pytest.raises(DIDUrlNotFoundError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type_sender",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
@pytest.mark.parametrize(
    "curve_type_recipient",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_authcrypt_unpack_sender_and_recipient_keys_incompatible_crypto(
    curve_type_sender, curve_type_recipient, resolvers_config_bob
):
    if curve_type_sender == curve_type_recipient:
        return
    frm_kid = get_key_agreement_methods(Person.ALICE, curve_type_sender)[0].id
    to_kids = [
        s.kid for s in get_key_agreement_secrets(Person.BOB, curve_type_recipient)
    ]
    with pytest.raises(IncompatibleCryptoError):
        res = [
            r
            async for r in find_authcrypt_unpack_sender_and_recipient_keys(
                frm_kid, to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected IncompatibleCryptoError but got " + str(res))
