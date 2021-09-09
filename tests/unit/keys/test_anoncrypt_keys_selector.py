import pytest

from didcomm.core.keys.anoncrypt_keys_selector import (
    find_anoncrypt_pack_recipient_public_keys,
    find_anoncrypt_unpack_recipient_private_keys,
)
from didcomm.errors import DIDDocNotResolvedError, DIDUrlNotFoundError
from tests.test_vectors.common import BOB_DID
from tests.test_vectors.did_doc.did_doc_bob import DID_DOC_BOB_WITH_NO_SECRETS
from tests.test_vectors.utils import (
    Person,
    get_key_agreement_secrets,
    KeyAgreementCurveType,
    get_key_agreement_methods,
    get_key_agreement_methods_not_in_secrets,
)


@pytest.mark.asyncio
async def test_find_anoncrypt_pack_recipient_public_keys_by_did_positive(
    resolvers_config_bob,
):
    # expect all keys of the same type as the first key
    expected = get_key_agreement_methods(Person.BOB, KeyAgreementCurveType.X25519)
    res = await find_anoncrypt_pack_recipient_public_keys(BOB_DID, resolvers_config_bob)
    assert res == expected
    assert expected[0] == DID_DOC_BOB_WITH_NO_SECRETS.verification_methods[0]


@pytest.mark.asyncio
async def test_find_anoncrypt_pack_recipient_public_keys_by_kid_positive(
    resolvers_config_bob,
):
    for vm in DID_DOC_BOB_WITH_NO_SECRETS.verification_methods:
        res = await find_anoncrypt_pack_recipient_public_keys(
            vm.id, resolvers_config_bob
        )
        assert res == [vm]


@pytest.mark.asyncio
async def test_find_anoncrypt_pack_recipient_public_keys_by_did_unknown_did(
    resolvers_config_bob,
):
    with pytest.raises(DIDDocNotResolvedError):
        await find_anoncrypt_pack_recipient_public_keys(
            "did:example:unknown", resolvers_config_bob
        )


@pytest.mark.asyncio
async def test_find_anoncrypt_pack_recipient_public_keys_by_kid_unknown_did(
    resolvers_config_bob,
):
    with pytest.raises(DIDDocNotResolvedError):
        await find_anoncrypt_pack_recipient_public_keys(
            "did:example:unknown#key-1", resolvers_config_bob
        )


@pytest.mark.asyncio
async def test_find_anoncrypt_pack_recipient_public_keys_by_kid_unknown_kid(
    resolvers_config_bob,
):
    with pytest.raises(DIDUrlNotFoundError):
        await find_anoncrypt_pack_recipient_public_keys(
            BOB_DID + "#unknown-key-1", resolvers_config_bob
        )


@pytest.mark.asyncio
async def test_find_anoncrypt_unpack_recipient_private_keys_positive_single_key(
    resolvers_config_bob,
):
    for s in get_key_agreement_secrets(Person.BOB):
        res = [
            s
            async for s in find_anoncrypt_unpack_recipient_private_keys(
                [s.kid], resolvers_config_bob
            )
        ]
        assert res == [s]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P384,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_anoncrypt_unpack_recipient_private_keys_positive_multiple_keys(
    curve_type, resolvers_config_bob
):
    secrets = get_key_agreement_secrets(Person.BOB, curve_type)
    to_kids = [s.kid for s in secrets]
    res = [
        s
        async for s in find_anoncrypt_unpack_recipient_private_keys(
            to_kids, resolvers_config_bob
        )
    ]
    assert res == secrets


@pytest.mark.asyncio
async def test_find_anoncrypt_unpack_recipient_private_keys_all_dids_unknown(
    resolvers_config_bob,
):
    with pytest.raises(DIDUrlNotFoundError):
        to_kids = ["did:example:unknown1#key-1", "did:example:unknown2#key-1"]
        res = [
            s
            async for s in find_anoncrypt_unpack_recipient_private_keys(
                to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
async def test_find_anoncrypt_unpack_recipient_private_keys_all_kids_unknown(
    resolvers_config_bob,
):
    with pytest.raises(DIDUrlNotFoundError):
        to_kids = [BOB_DID + "#unknown-key-1", BOB_DID + "#unknown-key-2"]
        res = [
            s
            async for s in find_anoncrypt_unpack_recipient_private_keys(
                to_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P384,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_anoncrypt_unpack_recipient_private_keys_all_not_in_secrets(
    curve_type, resolvers_config_bob
):
    not_in_secrets_kids = [
        vm.id for vm in get_key_agreement_methods_not_in_secrets(Person.BOB, curve_type)
    ]
    with pytest.raises(DIDUrlNotFoundError):
        res = [
            s
            async for s in find_anoncrypt_unpack_recipient_private_keys(
                not_in_secrets_kids, resolvers_config_bob
            )
        ]
        raise AssertionError("Expected DIDUrlNotFoundError but got " + str(res))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P384,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_anoncrypt_unpack_recipient_private_keys_known_and_unknown(
    curve_type, resolvers_config_bob
):
    secrets = get_key_agreement_secrets(Person.BOB, curve_type)
    valid_kids = [s.kid for s in secrets]
    to_kids = ["did:example:unknown1#key-1", BOB_DID + "#unknown-key-2"] + valid_kids
    res = [
        s
        async for s in find_anoncrypt_unpack_recipient_private_keys(
            to_kids, resolvers_config_bob
        )
    ]
    assert res == secrets


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "curve_type",
    [
        KeyAgreementCurveType.X25519,
        KeyAgreementCurveType.P256,
        KeyAgreementCurveType.P384,
        KeyAgreementCurveType.P521,
    ],
)
async def test_find_anoncrypt_unpack_recipient_private_keys_in_secrets_and_not(
    curve_type, resolvers_config_bob
):
    secrets = get_key_agreement_secrets(Person.BOB, curve_type)
    valid_kids = [s.kid for s in secrets]
    not_in_secrets_kids = [
        vm.id for vm in get_key_agreement_methods_not_in_secrets(Person.BOB, curve_type)
    ]
    to_kids = not_in_secrets_kids + valid_kids
    res = [
        s
        async for s in find_anoncrypt_unpack_recipient_private_keys(
            to_kids, resolvers_config_bob
        )
    ]
    assert res == secrets


# currently no exception is raised here, as default mode of key processing is one by one
# and it's sufficient to decrypt for at least one key.
# If decryption by all keys is required, an error will be raised for incompatible epk and static keys during decryption.
@pytest.mark.asyncio
async def test_find_anoncrypt_unpack_recipient_private_keys_different_curves(
    resolvers_config_bob,
):
    secrets = get_key_agreement_secrets(Person.BOB, KeyAgreementCurveType.ALL)
    kids = [s.kid for s in secrets]
    res = [
        s
        async for s in find_anoncrypt_unpack_recipient_private_keys(
            kids, resolvers_config_bob
        )
    ]
    assert res == secrets
