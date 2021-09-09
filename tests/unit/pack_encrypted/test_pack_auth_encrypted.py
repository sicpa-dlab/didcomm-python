import pytest

from didcomm.common.algorithms import AuthCryptAlg, AnonCryptAlg
from didcomm.core.utils import is_did_url
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.common import BOB_DID, ALICE_DID, TEST_MESSAGE
from tests.test_vectors.utils import (
    get_key_agreement_methods_in_secrets,
    Person,
    get_key_agreement_methods,
    KeyAgreementCurveType,
    get_auth_methods_in_secrets,
)

AUTH_ALG_PARAMS = [None, AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW]
ANON_ALG_PARAMS = [
    None,
    AnonCryptAlg.XC20P_ECDH_ES_A256KW,
    AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
    AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
]
SIGN_FRM_PARAMS = [None, ALICE_DID] + [
    vm.id for vm in get_auth_methods_in_secrets(Person.ALICE)
]
CURVES_TYPES = [
    KeyAgreementCurveType.X25519,
    KeyAgreementCurveType.P256,
    KeyAgreementCurveType.P521,
    KeyAgreementCurveType.P384,
]


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_alg", AUTH_ALG_PARAMS)
@pytest.mark.parametrize("anon_alg", ANON_ALG_PARAMS)
@pytest.mark.parametrize("sign_frm", SIGN_FRM_PARAMS)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_authcrypt_sender_did_recipient_did(
    auth_alg,
    anon_alg,
    sign_frm,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
):
    await check_authcrypt(
        frm=ALICE_DID,
        to=BOB_DID,
        sign_frm=sign_frm,
        auth_alg=auth_alg,
        anon_alg=anon_alg,
        protect_sender_id=protect_sender_id,
        resolvers_config_alice=resolvers_config_alice,
        resolvers_config_bob=resolvers_config_bob,
        curve_type=KeyAgreementCurveType.X25519,  # the first Alice key is X25519
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "to",
    [
        vm.id
        for vm in get_key_agreement_methods_in_secrets(
            Person.BOB, KeyAgreementCurveType.X25519
        )
    ],
)
@pytest.mark.parametrize("auth_alg", AUTH_ALG_PARAMS)
@pytest.mark.parametrize("anon_alg", ANON_ALG_PARAMS)
@pytest.mark.parametrize("sign_frm", SIGN_FRM_PARAMS)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_authcrypt_sender_did_recipient_kid(
    to,
    auth_alg,
    anon_alg,
    sign_frm,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
):
    await check_authcrypt(
        frm=ALICE_DID,
        to=to,
        sign_frm=sign_frm,
        auth_alg=auth_alg,
        anon_alg=anon_alg,
        protect_sender_id=protect_sender_id,
        resolvers_config_alice=resolvers_config_alice,
        resolvers_config_bob=resolvers_config_bob,
        curve_type=KeyAgreementCurveType.X25519,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("curve_type", CURVES_TYPES)
@pytest.mark.parametrize("auth_alg", AUTH_ALG_PARAMS)
@pytest.mark.parametrize("anon_alg", ANON_ALG_PARAMS)
@pytest.mark.parametrize("sign_frm", SIGN_FRM_PARAMS)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_authcrypt_sender_kid_recipient_did(
    curve_type,
    auth_alg,
    anon_alg,
    sign_frm,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
):
    for frm in [
        vm.id for vm in get_key_agreement_methods_in_secrets(Person.ALICE, curve_type)
    ]:
        await check_authcrypt(
            frm=frm,
            to=BOB_DID,
            sign_frm=sign_frm,
            auth_alg=auth_alg,
            anon_alg=anon_alg,
            protect_sender_id=protect_sender_id,
            resolvers_config_alice=resolvers_config_alice,
            resolvers_config_bob=resolvers_config_bob,
            curve_type=curve_type,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("curve_type", CURVES_TYPES)
@pytest.mark.parametrize("auth_alg", AUTH_ALG_PARAMS)
@pytest.mark.parametrize("anon_alg", ANON_ALG_PARAMS)
@pytest.mark.parametrize("sign_frm", SIGN_FRM_PARAMS)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_authcrypt_sender_kid_recipient_kid(
    curve_type,
    auth_alg,
    anon_alg,
    sign_frm,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
):
    for frm in [
        vm.id for vm in get_key_agreement_methods_in_secrets(Person.ALICE, curve_type)
    ]:
        for to in [
            vm.id for vm in get_key_agreement_methods_in_secrets(Person.BOB, curve_type)
        ]:
            await check_authcrypt(
                frm=frm,
                to=to,
                sign_frm=sign_frm,
                auth_alg=auth_alg,
                anon_alg=anon_alg,
                protect_sender_id=protect_sender_id,
                resolvers_config_alice=resolvers_config_alice,
                resolvers_config_bob=resolvers_config_bob,
                curve_type=curve_type,
            )


async def check_authcrypt(
    frm,
    to,
    sign_frm,
    auth_alg,
    anon_alg,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
    curve_type,
):
    pack_config = PackEncryptedConfig(protect_sender_id=protect_sender_id)
    if auth_alg:
        pack_config.enc_alg_auth = auth_alg
    if anon_alg:
        pack_config.enc_alg_anon = anon_alg
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=TEST_MESSAGE,
        frm=frm,
        to=to,
        sign_frm=sign_frm,
        pack_config=pack_config,
    )

    expected_to = [to]
    if not is_did_url(to):
        expected_to = [
            vm.id for vm in get_key_agreement_methods(Person.BOB, curve_type)
        ]

    expected_frm = frm
    if not is_did_url(frm):
        expected_frm = get_key_agreement_methods_in_secrets(Person.ALICE)[0].id

    expected_sign_frm = None
    if sign_frm is not None and sign_frm != ALICE_DID:
        expected_sign_frm = sign_frm
    if sign_frm == ALICE_DID:
        expected_sign_frm = get_auth_methods_in_secrets(Person.ALICE)[0].id

    assert pack_result.from_kid == expected_frm
    assert pack_result.to_kids == expected_to
    assert pack_result.sign_from_kid == expected_sign_frm
    assert pack_result.packed_msg is not None

    unpack_res = await unpack(
        resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg
    )

    expected_alg = auth_alg or AuthCryptAlg.A256CBC_HS512_ECDH_1PU_A256KW
    expected_anon_alg = anon_alg or AnonCryptAlg.XC20P_ECDH_ES_A256KW
    if not protect_sender_id:
        expected_anon_alg = None
    assert unpack_res.message == TEST_MESSAGE
    assert unpack_res.metadata.enc_alg_anon == expected_anon_alg
    assert unpack_res.metadata.enc_alg_auth == expected_alg
    assert unpack_res.metadata.anonymous_sender == protect_sender_id
    assert unpack_res.metadata.encrypted
    assert unpack_res.metadata.non_repudiation == (sign_frm is not None)
    assert not unpack_res.metadata.re_wrapped_in_forward
    assert unpack_res.metadata.authenticated
