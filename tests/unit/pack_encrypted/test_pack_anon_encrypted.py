import pytest

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack
from tests.test_vectors.common import TEST_MESSAGE, BOB_DID
from tests.test_vectors.utils import (
    get_key_agreement_methods,
    Person,
    KeyAgreementCurveType,
    get_key_agreement_methods_in_secrets,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "alg",
    [
        AnonCryptAlg.XC20P_ECDH_ES_A256KW,
        AnonCryptAlg.A256GCM_ECDH_ES_A256KW,
        AnonCryptAlg.A256CBC_HS512_ECDH_ES_A256KW,
    ],
)
@pytest.mark.parametrize(
    "to", [BOB_DID] + [vm.id for vm in get_key_agreement_methods_in_secrets(Person.BOB)]
)
@pytest.mark.parametrize("protect_sender_id", [True, False])
async def test_anoncrypt(
    alg, to, protect_sender_id, resolvers_config_alice, resolvers_config_bob
):
    pack_result = await pack_encrypted(
        resolvers_config=resolvers_config_alice,
        message=TEST_MESSAGE,
        to=to,
        pack_config=PackEncryptedConfig(
            enc_alg_anon=alg, protect_sender_id=protect_sender_id
        ),
    )

    expected_to = (
        [to]
        if to != BOB_DID
        else [
            vm.id
            for vm in get_key_agreement_methods(
                Person.BOB, KeyAgreementCurveType.X25519
            )
        ]
    )
    assert pack_result.from_kid is None
    assert pack_result.to_kids == expected_to
    assert pack_result.sign_from_kid is None
    assert pack_result.packed_msg is not None

    unpack_res = await unpack(
        resolvers_config=resolvers_config_bob, packed_msg=pack_result.packed_msg
    )
    assert unpack_res.message == TEST_MESSAGE
