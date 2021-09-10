import pytest

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.common import BOB_DID, ALICE_DID
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    attachment_json_msg,
    attachment_multi_1_msg,
    minimal_msg,
)
from tests.test_vectors.utils import (
    get_key_agreement_methods,
    Person,
    KeyAgreementCurveType,
    get_key_agreement_methods_in_secrets,
    get_auth_methods_in_secrets,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "msg",
    [TEST_MESSAGE, minimal_msg(), attachment_multi_1_msg(), attachment_json_msg()],
)
@pytest.mark.parametrize(
    "alg",
    [
        None,
        AnonCryptAlg.XC20P_ECDH_ES_A256KW,
        AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
        AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
    ],
)
@pytest.mark.parametrize(
    "to", [BOB_DID] + [vm.id for vm in get_key_agreement_methods_in_secrets(Person.BOB)]
)
@pytest.mark.parametrize(
    "sign_frm",
    [None, ALICE_DID] + [vm.id for vm in get_auth_methods_in_secrets(Person.ALICE)],
)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_anoncrypt(
    msg,
    alg,
    to,
    sign_frm,
    protect_sender_id,
    resolvers_config_alice,
    resolvers_config_bob,
):
    pack_config = PackEncryptedConfig(protect_sender_id=protect_sender_id)
    if alg:
        pack_config.enc_alg_anon = alg
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=msg,
        to=to,
        sign_frm=sign_frm,
        pack_config=pack_config,
    )

    expected_to = [to]
    if to == BOB_DID:
        expected_to = [
            vm.id
            for vm in get_key_agreement_methods(
                Person.BOB, KeyAgreementCurveType.X25519
            )
        ]
    expected_sign_frm = None
    if sign_frm is not None and sign_frm != ALICE_DID:
        expected_sign_frm = sign_frm
    if sign_frm == ALICE_DID:
        expected_sign_frm = get_auth_methods_in_secrets(Person.ALICE)[0].id

    assert pack_result.from_kid is None
    assert pack_result.to_kids == expected_to
    assert pack_result.sign_from_kid == expected_sign_frm
    assert pack_result.packed_msg is not None

    unpack_res = await unpack(
        resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg
    )
    expected_alg = alg or AnonCryptAlg.XC20P_ECDH_ES_A256KW
    assert unpack_res.message == msg
    assert unpack_res.metadata.enc_alg_anon == expected_alg
    assert unpack_res.metadata.enc_alg_auth is None
    assert unpack_res.metadata.anonymous_sender
    assert unpack_res.metadata.encrypted
    assert unpack_res.metadata.non_repudiation == (sign_frm is not None)
    assert not unpack_res.metadata.re_wrapped_in_forward
    assert not unpack_res.metadata.authenticated
